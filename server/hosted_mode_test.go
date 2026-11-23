package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"p3y/agent"
	"p3y/benchmark"
	"p3y/db"
)

func TestFromEnvProfilesMultiKeyAndDeepSeek(t *testing.T) {
	t.Setenv("P3Y_LLM_PROVIDER", "")
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("DEEPSEEK_API_KEY", "sk-ds-one, sk-ds-two, sk-ds-one")
	t.Setenv("P3Y_LLM_API_KEYS", "")
	t.Setenv("P3Y_LLM_BASE_URL", "http://api.deepseek.com.tsecbench.gw/v1/chat/completions")
	t.Setenv("P3Y_LLM_MODEL", "")
	t.Setenv("P3Y_LLM_MAX_TOKENS", "4096")
	t.Setenv("P3Y_LLM_CONTEXT_WINDOW_K", "128")
	t.Setenv("P3Y_LLM_THINKING_TYPE", "enabled")
	t.Setenv("P3Y_LLM_REASONING_EFFORT", "medium")

	cfgs, ok := agent.FromEnvProfiles()
	if !ok || len(cfgs) != 2 {
		t.Fatalf("expected 2 deduplicated DeepSeek profiles, got ok=%v len=%d (%+v)", ok, len(cfgs), cfgs)
	}
	if cfgs[0].Provider() != "openai" || cfgs[0].Model != "deepseek-chat" {
		t.Fatalf("unexpected inferred provider/model: %s / %s", cfgs[0].Provider(), cfgs[0].Model)
	}
	if cfgs[0].BaseURL != "http://api.deepseek.com.tsecbench.gw/v1" {
		t.Fatalf("expected normalized gateway BaseURL without /chat/completions, got %q", cfgs[0].BaseURL)
	}
	if cfgs[0].APIKey != "sk-ds-one" || cfgs[1].APIKey != "sk-ds-two" {
		t.Fatalf("unexpected failover keys: %q, %q", cfgs[0].APIKey, cfgs[1].APIKey)
	}
	if cfgs[0].MaxTokens != 4096 || cfgs[0].ContextWindowK != 128 || cfgs[0].ThinkingType != "enabled" || cfgs[0].ReasoningEffort != "medium" {
		t.Fatalf("unexpected extra env fields: %+v", cfgs[0])
	}
}

func TestHostedBenchmarkAutoBootstrapAndTipsSkip(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { m.Close() })

	mockTSec := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("BENCHMARK_TOKEN") != "tok-hosted-auto" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/openapi/v1/agent/whoami":
			_, _ = w.Write([]byte(`{"agent_name":"p3y-hosted","max_environments":2,"active_environments":0,"competition_enabled":true}`))
		case "/openapi/v1/challenges":
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{
					"unique_code":        "ch_hard_1",
					"description":        "hard",
					"difficulty":         "Hard",
					"level":              3,
					"total_score":        500,
					"flag_count":         1,
					"correct_flag_count": 0,
					"is_completed":       true,
					"container_status":   "stopped",
					"container_addr":     []string{},
				},
			})
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer mockTSec.Close()

	// Configure hosted environment BEFORE server.New so the real startup path runs auto-bootstrap.
	t.Setenv("P3Y_HOSTED_MODE", "1")
	t.Setenv("BENCHMARK_BASE_URL", mockTSec.URL)
	t.Setenv("BENCHMARK_TOKEN", "tok-hosted-auto")
	t.Setenv("P3Y_BENCH_CHALLENGE_TIMEOUT", "1200")
	t.Setenv("P3Y_BENCH_MAX_CONCURRENT", "2")
	t.Setenv("P3Y_BENCH_EXIT_ON_DONE", "1")

	if err := m.pg.SeedDefaultTips(t.Context()); err != nil {
		t.Fatalf("SeedDefaultTips under hosted mode: %v", err)
	}
	// Isolate from any uncleaned 'running' sessions left by earlier shared-DB tests.
	_, _ = m.pg.Exec(`UPDATE benchmark_sessions SET status='stopped' WHERE status='running'`)

	td := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	s := New(ctx, m, td, td, td)

	t.Cleanup(func() {
		sessions, _ := m.pg.ListBenchmarkSessions(context.Background())
		for _, item := range sessions {
			if item != nil && item.BaseURL == mockTSec.URL && item.Token == "tok-hosted-auto" {
				s.bench.stopSession(item.ID, "stopped", "test cleanup")
				_, _ = m.pg.Exec(`DELETE FROM benchmark_sessions WHERE id=$1`, item.ID)
			}
		}
	})

	// Already-completed single challenge triggers session completion and BenchmarkDone() notification.
	select {
	case <-s.BenchmarkDone():
	case <-time.After(12 * time.Second):
		t.Fatal("timed out waiting for auto-bootstrapped hosted benchmark to complete and signal BenchmarkDone()")
	}

	sessions, err := m.pg.ListBenchmarkSessions(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var created *db.BenchmarkSession
	for _, item := range sessions {
		if item != nil && item.BaseURL == mockTSec.URL && item.Token == "tok-hosted-auto" {
			created = item
			break
		}
	}
	if created == nil {
		t.Fatal("expected server.New to auto-create and start hosted benchmark session")
	}
	if created.Provider != "tsecbench" || created.MaxConcurrent != 2 || created.PerChallengeTimeout != 1200 {
		t.Fatalf("unexpected created session config: %+v", created)
	}
	if !strings.EqualFold(created.Status, "completed") {
		t.Fatalf("expected completed status, got %q", created.Status)
	}
}

func TestHostedBenchmarkDefaultBudgetAndNoManualWaitDeadlock(t *testing.T) {
	t.Setenv("P3Y_HOSTED_MODE", "0")
	t.Setenv("P3Y_BENCH_EXIT_ON_DONE", "")
	t.Setenv("P3Y_BENCH_MAX_RETRIES", "")
	if got := benchmarkMaxAutoRetries(); got != 3 {
		t.Fatalf("interactive default max retries = %d, want 3", got)
	}

	t.Setenv("P3Y_HOSTED_MODE", "1")
	if got := benchmarkMaxAutoRetries(); got != 5 {
		t.Fatalf("hosted default max retries = %d, want 5", got)
	}
	t.Setenv("P3Y_BENCH_MAX_RETRIES", "-1")
	if got := benchmarkMaxAutoRetries(); got != -1 {
		t.Fatalf("unlimited max retries = %d, want -1", got)
	}
	t.Setenv("P3Y_BENCH_MAX_RETRIES", "2")
	if got := benchmarkMaxAutoRetries(); got != 2 {
		t.Fatalf("explicit max retries = %d, want 2", got)
	}

	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { m.Close() })

	mockTSec := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/openapi/v1/agent/whoami":
			_, _ = w.Write([]byte(`{"agent_name":"p3y-hosted","max_environments":3,"active_environments":0,"competition_enabled":true}`))
		case "/openapi/v1/challenges":
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{
					"unique_code":        "ch_exhausted_1",
					"description":        "exhausted problem",
					"difficulty":         "Hard",
					"level":              3,
					"total_score":        500,
					"flag_count":         1,
					"correct_flag_count": 0,
					"is_completed":       false,
					"container_status":   "stopped",
					"container_addr":     []string{},
				},
			})
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer mockTSec.Close()

	// Unset P3Y_BENCH_CHALLENGE_TIMEOUT so default 5400s applies, and leave BENCHMARK_BASE_URL unset for this session test.
	t.Setenv("P3Y_BENCH_CHALLENGE_TIMEOUT", "")
	t.Setenv("P3Y_BENCH_EXIT_ON_DONE", "1")
	t.Setenv("BENCHMARK_BASE_URL", "")
	t.Setenv("BENCHMARK_TOKEN", "")

	sess, err := m.pg.CreateBenchmarkSession(t.Context(), db.BenchmarkSessionCreate{
		Name:     "hosted-exhausted-test",
		Provider: "tsecbench",
		BaseURL:  mockTSec.URL,
		Token:    "tok-exhausted",
	})
	if err != nil {
		t.Fatalf("CreateBenchmarkSession: %v", err)
	}
	t.Cleanup(func() {
		_, _ = m.pg.Exec(`DELETE FROM benchmark_sessions WHERE id=$1`, sess.ID)
	})

	if err := m.pg.SyncBenchmarkChallenges(t.Context(), sess.ID, []db.BenchmarkChallengeUpsert{{
		UniqueCode:  "ch_exhausted_1",
		Description: "exhausted problem",
		Difficulty:  "Hard",
		Level:       3,
		TotalScore:  500,
		FlagCount:   1,
	}}); err != nil {
		t.Fatalf("SyncBenchmarkChallenges: %v", err)
	}
	deadTask, err := m.CreateTaskWithOptions("dead", "solve", db.TaskCreateOptions{
		Name:               "[ch_exhausted_1] dead",
		ZeroTouch:          true,
		BenchmarkSessionID: &sess.ID,
	})
	if err != nil {
		t.Fatalf("CreateTaskWithOptions: %v", err)
	}
	_ = m.SetTaskStatus(deadTask.ID, "failed")
	tid, _ := strconv.ParseInt(deadTask.ID, 10, 64)
	if err := m.pg.BindBenchmarkChallengeTask(t.Context(), sess.ID, "ch_exhausted_1", tid); err != nil {
		t.Fatalf("BindBenchmarkChallengeTask: %v", err)
	}
	if err := m.pg.ScheduleBenchmarkChallengeRetry(t.Context(), sess.ID, "ch_exhausted_1", nil, 2, ""); err != nil {
		t.Fatalf("ScheduleBenchmarkChallengeRetry: %v", err)
	}
	// Isolate from any uncleaned 'running' sessions left by earlier shared-DB tests, then mark ours running.
	_, _ = m.pg.Exec(`UPDATE benchmark_sessions SET status='stopped' WHERE status='running' AND id <> $1`, sess.ID)
	if err := m.pg.UpdateBenchmarkSessionStatus(t.Context(), sess.ID, "running", ""); err != nil {
		t.Fatalf("UpdateBenchmarkSessionStatus: %v", err)
	}

	td := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	s := New(ctx, m, td, td, td)
	t.Cleanup(func() {
		s.bench.stopSession(sess.ID, "stopped", "cleanup")
		sessions, _ := m.pg.ListBenchmarkSessions(context.Background())
		for _, item := range sessions {
			if item != nil && item.Token == "tok-boot-5400" {
				s.bench.stopSession(item.ID, "stopped", "cleanup")
				_, _ = m.pg.Exec(`DELETE FROM benchmark_sessions WHERE id=$1`, item.ID)
			}
		}
	})

	select {
	case <-s.BenchmarkDone():
	case <-time.After(12 * time.Second):
		t.Fatal("expected hosted mode session with only exhausted unsolved challenges to finish cleanly instead of hanging on manual requeue")
	}

	storedSess, err := m.pg.GetBenchmarkSession(t.Context(), sess.ID)
	if err != nil || storedSess == nil {
		t.Fatalf("GetBenchmarkSession: %v", err)
	}
	if !strings.EqualFold(storedSess.Status, "completed") {
		t.Fatalf("expected exhausted hosted session to finalize as completed, got %q", storedSess.Status)
	}
	storedCh, err := m.pg.GetBenchmarkChallenge(t.Context(), sess.ID, "ch_exhausted_1")
	if err != nil || storedCh == nil {
		t.Fatalf("GetBenchmarkChallenge: %v", err)
	}
	if strings.Contains(storedCh.LastError, "等待手动重排") || !strings.Contains(storedCh.LastError, "已达重试上限") {
		t.Fatalf("unexpected hosted exhausted message: %q", storedCh.LastError)
	}

	// Verify autoBootstrapFromEnv default PerChallengeTimeout is 5400 when unset.
	mockDone := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/openapi/v1/agent/whoami":
			_, _ = w.Write([]byte(`{"agent_name":"p3y-hosted","max_environments":3,"active_environments":0,"competition_enabled":true}`))
		case "/openapi/v1/challenges":
			_ = json.NewEncoder(w).Encode([]map[string]any{{
				"unique_code":  "ch_done_5400",
				"description":  "done",
				"is_completed": true,
			}})
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer mockDone.Close()
	t.Setenv("BENCHMARK_BASE_URL", mockDone.URL)
	t.Setenv("BENCHMARK_TOKEN", "tok-boot-5400")
	td2 := t.TempDir()
	ctx2, cancel2 := context.WithCancel(context.Background())
	t.Cleanup(cancel2)
	s2 := New(ctx2, m, td2, td2, td2)
	t.Cleanup(func() {
		sessions, _ := m.pg.ListBenchmarkSessions(context.Background())
		for _, item := range sessions {
			if item != nil && item.Token == "tok-boot-5400" {
				s2.bench.stopSession(item.ID, "stopped", "cleanup")
				_, _ = m.pg.Exec(`DELETE FROM benchmark_sessions WHERE id=$1`, item.ID)
			}
		}
	})
	select {
	case <-s2.BenchmarkDone():
	case <-time.After(12 * time.Second):
		t.Fatal("timed out waiting for auto-bootstrap default timeout check")
	}
	sessions, _ := m.pg.ListBenchmarkSessions(t.Context())
	found5400 := false
	for _, item := range sessions {
		if item != nil && item.Token == "tok-boot-5400" {
			found5400 = true
			if item.PerChallengeTimeout != 5400 {
				t.Fatalf("expected default auto-bootstrap timeout=5400, got %d", item.PerChallengeTimeout)
			}
			if item.HintPolicy != "stagnant_only" {
				t.Fatalf("expected default auto-bootstrap hint_policy=stagnant_only, got %q", item.HintPolicy)
			}
		}
	}
	if !found5400 {
		t.Fatal("expected tok-boot-5400 session to be auto-created")
	}
}

func TestMultiStageBenchmarkFlagProgressAndDedup(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { m.Close() })

	submitted := map[string]bool{}
	mockTSec := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "POST" && r.URL.Path == "/openapi/v1/challenges/submit":
			var body struct {
				UniqueCode string `json:"unique_code"`
				Flag       string `json:"flag"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			switch body.Flag {
			case "flag{stage_1}":
				submitted["flag{stage_1}"] = true
				_ = json.NewEncoder(w).Encode(map[string]any{
					"correct": true, "awarded": 100, "cumulative_score": 100,
					"correct_flag_count": 1, "total_flag_count": 3,
				})
			case "flag{stage_2}":
				submitted["flag{stage_2}"] = true
				_ = json.NewEncoder(w).Encode(map[string]any{
					"correct": true, "awarded": 150, "cumulative_score": 250,
					"correct_flag_count": 2, "total_flag_count": 3,
				})
			case "flag{stage_3}":
				submitted["flag{stage_3}"] = true
				_ = json.NewEncoder(w).Encode(map[string]any{
					"correct": true, "awarded": 250, "cumulative_score": 500,
					"correct_flag_count": 3, "total_flag_count": 3,
				})
			default:
				w.WriteHeader(400)
				_ = json.NewEncoder(w).Encode(map[string]any{"code": "incorrect_flag", "message": "wrong"})
			}
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer mockTSec.Close()

	td := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	s := New(ctx, m, td, td, td)

	sess, err := m.pg.CreateBenchmarkSession(t.Context(), db.BenchmarkSessionCreate{
		Name: "multi-stage-test", Provider: "tsecbench", BaseURL: mockTSec.URL, Token: "tok-ms",
	})
	if err != nil {
		t.Fatalf("CreateBenchmarkSession: %v", err)
	}
	t.Cleanup(func() {
		s.bench.stopSession(sess.ID, "stopped", "cleanup")
		_, _ = m.pg.Exec(`DELETE FROM benchmark_sessions WHERE id=$1`, sess.ID)
	})
	if err := m.pg.SyncBenchmarkChallenges(t.Context(), sess.ID, []db.BenchmarkChallengeUpsert{{
		UniqueCode: "ms_chain_1", Title: "ms_chain_1", Description: "3-stage pentest",
		Difficulty: "Hard", FlagCount: 3, TotalScore: 500,
	}}); err != nil {
		t.Fatalf("SyncBenchmarkChallenges: %v", err)
	}

	taskObj, err := m.CreateTaskWithOptions("ms", "get all 3 flags", db.TaskCreateOptions{
		Name: "[ms_chain_1] multi", Mode: "ctf", ChallengeType: "web",
		CTFVerifyMode: db.CTFVerifyFlag, ZeroTouch: true, BenchmarkSessionID: &sess.ID,
	})
	if err != nil {
		t.Fatalf("CreateTaskWithOptions: %v", err)
	}
	tidNum, _ := strconv.ParseInt(taskObj.ID, 10, 64)
	if err := m.pg.BindBenchmarkChallengeTask(t.Context(), sess.ID, "ms_chain_1", tidNum); err != nil {
		t.Fatalf("BindBenchmarkChallengeTask: %v", err)
	}
	if err := s.ctfService().Sync(t.Context(), tidNum); err != nil {
		t.Fatalf("ctf Sync: %v", err)
	}
	execID := "exec-ms-" + taskObj.ID
	var ih string
	if err := m.pg.QueryRow(`SELECT ctf_input_hash FROM tasks WHERE id=$1`, tidNum).Scan(&ih); err != nil {
		t.Fatalf("query ctf_input_hash: %v", err)
	}
	if serr := m.pg.SaveCTFExecution(t.Context(), &db.CTFExecution{
		ID: execID, TaskID: tidNum, InputHash: ih, StartedAt: time.Now(),
	}); serr != nil {
		t.Fatalf("SaveCTFExecution: %v", serr)
	}

	// Verify multi-stage prompt injection triggers for FlagCount=3.
	if bctx := s.bench.contextForTask(t.Context(), tidNum, "worker"); !strings.Contains(bctx, "多阶段渗透接力指引") {
		t.Fatalf("expected multi-stage relay guidance in contextForTask, got %q", bctx)
	}

	submit := func(flag string) string {
		if _, err := m.pg.AddCTFCandidate(t.Context(), tidNum, execID, flag); err != nil {
			t.Fatalf("AddCTFCandidate(%s): %v", flag, err)
		}
		v, handled, herr := s.bench.handleFlagCandidate(t.Context(), tidNum, execID, flag, "")
		if !handled || herr != nil {
			t.Fatalf("handleFlagCandidate(%s) handled=%v err=%v", flag, handled, herr)
		}
		return v
	}

	// Pre-stage rejections accumulate until a stage flag succeeds, then reset to 0.
	_ = submit("flag{wrong_pre_1}")
	_ = submit("flag{wrong_pre_2}")
	if rej, _ := m.pg.CountRejectedBenchmarkSubmissions(t.Context(), sess.ID, "ms_chain_1"); rej != 2 {
		t.Fatalf("expected 2 consecutive rejections before stage 1, got %d", rej)
	}

	// Stage 1: flag 1 accepted, consecutive rejection count resets to 0, task stays running, prove_goal + RequireCTFAcceptedFlag block early finish!
	v1 := submit("flag{stage_1}")
	if !strings.Contains(v1, "阶段 Flag 验证通过") || !strings.Contains(v1, "严禁结束当前意图") {
		t.Fatalf("expected inline stage continuation message in verdict JSON, got %s", v1)
	}
	if rej, _ := m.pg.CountRejectedBenchmarkSubmissions(t.Context(), sess.ID, "ms_chain_1"); rej != 0 {
		t.Fatalf("expected consecutive rejections to reset to 0 after stage 1 flag accepted, got %d", rej)
	}
	if solved, req, ok := m.pg.BenchmarkTaskFlagProgress(t.Context(), tidNum, 0); !ok || solved != 1 || req != 3 {
		t.Fatalf("expected progress (1,3,true), got (%d,%d,%v)", solved, req, ok)
	}
	tAfter1, _ := m.pg.GetTask(tidNum)
	if tAfter1 == nil || tAfter1.Status == "done" {
		t.Fatalf("task must NOT become done at 1/3 flags, status=%+v", tAfter1)
	}

	ts := taskObj.Store
	goalID, err := ts.AddGoal(map[string]any{"text": "get all 3 flags"}, "root")
	if err != nil {
		t.Fatalf("AddGoal: %v", err)
	}
	factID, err := ts.AddNode("fact", map[string]any{"summary": "stage 1 flag accepted"}, 0, "confirmed", "worker", nil)
	if err != nil {
		t.Fatalf("AddFact: %v", err)
	}
	bundle1, err := ts.BuildGoalBundle(t.Context(), goalID)
	if err != nil {
		t.Fatalf("BuildGoalBundle: %v", err)
	}
	if err := db.RequireCTFAcceptedFlag(bundle1); err == nil || !strings.Contains(err.Error(), "1/3") {
		t.Fatalf("expected RequireCTFAcceptedFlag to block at 1/3, got %v", err)
	}

	plannerTools := agent.NewToolSet(ts, "planner")
	plannerTools.SetTaskID(tidNum)
	for _, tl := range plannerTools.PlannerTools() {
		if tl.Name() == "prove_goal" {
			res, perr := tl.Call(t.Context(), json.RawMessage(fmt.Sprintf(`{"goal_id":%d,"evidence_id":%d,"reason":"got 1"}`, goalID, factID)), nil)
			if perr != nil {
				t.Fatalf("prove_goal Call err: %v", perr)
			}
			if !strings.Contains(res.Flatten(), "1/3") {
				t.Fatalf("expected prove_goal to reject 1/3 early submit, got %s", res.Flatten())
			}
			break
		}
	}

	// Re-observing stage 1 flag must NOT turn accepted candidate into rejected.
	dupOut := submit("flag{stage_1}")
	if !strings.Contains(dupOut, `"already_accepted":true`) {
		t.Fatalf("expected already_accepted dedup response for flag 1, got %s", dupOut)
	}
	cands, _ := m.pg.CTFCandidates(t.Context(), tidNum)
	for _, c := range cands {
		if c.Value == "flag{stage_1}" && c.State != "accepted" {
			t.Fatalf("accepted flag 1 must stay accepted on re-submission, got state=%s notes=%q", c.State, c.Notes)
		}
	}

	// Stage 2 still incomplete (2/3); Stage 3 completes task cleanly (3/3).
	_ = submit("flag{stage_2}")
	if solved, req, ok := m.pg.BenchmarkTaskFlagProgress(t.Context(), tidNum, 0); !ok || solved != 2 || req != 3 {
		t.Fatalf("expected progress (2,3,true) at stage 2, got (%d,%d,%v)", solved, req, ok)
	}
	tAfter2, _ := m.pg.GetTask(tidNum)
	if tAfter2 == nil || tAfter2.Status == "done" {
		t.Fatalf("task must NOT become done at 2/3 flags, status=%+v", tAfter2)
	}
	_ = submit("flag{stage_3}")
	chEnd, _ := m.pg.GetBenchmarkChallenge(t.Context(), sess.ID, "ms_chain_1")
	if chEnd == nil || !chEnd.IsCompleted || chEnd.CorrectFlagCount != 3 {
		t.Fatalf("expected 3/3 completed challenge, got %+v", chEnd)
	}
	tEnd, _ := m.pg.GetTask(tidNum)
	if tEnd == nil || tEnd.Status != "done" {
		t.Fatalf("expected task status=done once 3/3 flags accepted, got %+v", tEnd)
	}
	if err := db.RequireCTFAcceptedFlag(&db.EvidenceBundle{
		CTF: &db.CTFGoalProof{
			InputHash:     ih,
			RequiredFlags: 3,
			SolvedFlags:   3,
			Accepted: []db.CTFCandidate{
				{Kind: db.CTFCandidateFlag, Value: "flag{stage_1}"},
				{Kind: db.CTFCandidateFlag, Value: "flag{stage_2}"},
				{Kind: db.CTFCandidateFlag, Value: "flag{stage_3}"},
			},
		},
	}); err != nil {
		t.Fatalf("expected RequireCTFAcceptedFlag to pass at 3/3, got %v", err)
	}
}

func TestBenchmarkFlagPrefixNormalizationZeroPenalty(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { m.Close() })

	var received []string
	mockTSec := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "POST" && r.URL.Path == "/openapi/v1/challenges/submit" {
			var body struct {
				UniqueCode string `json:"unique_code"`
				Flag       string `json:"flag"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			received = append(received, body.Flag)
			if body.Flag == "flag{DES1R3_DRIVES_INT0_VAPORW@VES}" {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"correct": true, "awarded": 200, "cumulative_score": 200,
					"correct_flag_count": 1, "total_flag_count": 1, "completed": true,
				})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"correct": false, "message": "wrong flag"})
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer mockTSec.Close()

	sess, err := m.pg.CreateBenchmarkSession(t.Context(), db.BenchmarkSessionCreate{
		Name:                "prefix-norm-test",
		Provider:            "tsecbench",
		BaseURL:             mockTSec.URL,
		Token:               "tok-prefix-norm",
		MaxConcurrent:       1,
		PerChallengeTimeout: 1800,
	})
	if err != nil {
		t.Fatalf("CreateBenchmarkSession: %v", err)
	}
	t.Cleanup(func() { _, _ = m.pg.Exec(`DELETE FROM benchmark_sessions WHERE id=$1`, sess.ID) })

	if err := m.pg.SyncBenchmarkChallenges(t.Context(), sess.ID, []db.BenchmarkChallengeUpsert{{
		UniqueCode: "sctf_vaporwaves",
		Title:      "sctf_vaporwaves",
		Category:   "misc",
		TotalScore: 200,
		FlagCount:  1,
	}}); err != nil {
		t.Fatalf("SyncBenchmarkChallenges: %v", err)
	}
	taskObj, err := m.CreateTaskWithOptions("sctf_vaporwaves", "find flag", db.TaskCreateOptions{Mode: "ctf", ChallengeType: "misc"})
	if err != nil {
		t.Fatalf("CreateTaskWithOptions: %v", err)
	}
	tidNum, _ := strconv.ParseInt(taskObj.ID, 10, 64)
	t.Cleanup(func() { _, _ = m.DeleteTask(taskObj.ID, DeleteTaskOptions{}) })
	_ = m.pg.BindBenchmarkChallengeTask(t.Context(), sess.ID, "sctf_vaporwaves", tidNum)

	td := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	s := New(ctx, m, td, td, td)
	ch, _ := m.pg.GetBenchmarkChallenge(t.Context(), sess.ID, "sctf_vaporwaves")

	// 1. Rejected custom-prefix flag must try flag{...} once WITHOUT double-counting rejections.
	wrongOut, handled, err := s.bench.submitToPlatform(t.Context(), sess, ch, tidNum, benchmark.SubmitRequest{
		UniqueCode: "sctf_vaporwaves",
		Flag:       "SCTF{WRONG_BODY}",
	}, "SCTF{WRONG_BODY}")
	if err != nil || !handled {
		t.Fatalf("submit wrong custom prefix: handled=%v err=%v", handled, err)
	}
	if !strings.Contains(wrongOut, "flag{...}") {
		t.Fatalf("expected fallback note in rejection response, got %s", wrongOut)
	}
	if len(received) != 2 || received[0] != "SCTF{WRONG_BODY}" || received[1] != "flag{WRONG_BODY}" {
		t.Fatalf("expected raw then flag{...} fallback attempts, got %v", received)
	}
	rejCount, err := m.pg.CountRejectedBenchmarkSubmissions(t.Context(), sess.ID, "sctf_vaporwaves")
	if err != nil || rejCount != 1 {
		t.Fatalf("expected zero-penalty fallback to record only 1 rejection, got %d (err=%v)", rejCount, err)
	}

	// 2. Real Morse flag with SCTF{...} rejected by judge -> transparent fallback to flag{...} succeeds!
	ch, _ = m.pg.GetBenchmarkChallenge(t.Context(), sess.ID, "sctf_vaporwaves")
	okOut, handled, err := s.bench.submitToPlatform(t.Context(), sess, ch, tidNum, benchmark.SubmitRequest{
		UniqueCode: "sctf_vaporwaves",
		Flag:       "SCTF{DES1R3_DRIVES_INT0_VAPORW@VES}",
	}, "SCTF{DES1R3_DRIVES_INT0_VAPORW@VES}")
	if err != nil || !handled {
		t.Fatalf("submit valid SCTF flag: handled=%v err=%v", handled, err)
	}
	if !strings.Contains(okOut, `"correct":true`) {
		t.Fatalf("expected normalized fallback to succeed, got %s", okOut)
	}
	chEnd, _ := m.pg.GetBenchmarkChallenge(t.Context(), sess.ID, "sctf_vaporwaves")
	if chEnd == nil || !chEnd.IsCompleted || chEnd.CorrectFlagCount != 1 {
		t.Fatalf("expected challenge completed via normalized prefix fallback, got %+v", chEnd)
	}
}

func TestBenchmarkEmptyHintMarksUsedNoSpam(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { m.Close() })

	hintCalls := 0
	mockTSec := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/openapi/v1/challenges/hint" {
			hintCalls++
			_, _ = w.Write([]byte(`{"unique_code":"Aperture","hint":null}`))
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer mockTSec.Close()

	sess, err := m.pg.CreateBenchmarkSession(t.Context(), db.BenchmarkSessionCreate{
		Name:                "empty-hint-no-spam",
		Provider:            "tsecbench",
		BaseURL:             mockTSec.URL,
		Token:               "tok-empty-hint",
		MaxConcurrent:       1,
		HintPolicy:          "stagnant_only",
		PerChallengeTimeout: 1200,
	})
	if err != nil {
		t.Fatalf("CreateBenchmarkSession: %v", err)
	}
	t.Cleanup(func() { _, _ = m.pg.Exec(`DELETE FROM benchmark_sessions WHERE id=$1`, sess.ID) })

	if err := m.pg.SyncBenchmarkChallenges(t.Context(), sess.ID, []db.BenchmarkChallengeUpsert{{
		UniqueCode: "Aperture",
		Title:      "Aperture",
		Category:   "web",
		TotalScore: 500,
		FlagCount:  1,
	}}); err != nil {
		t.Fatalf("SyncBenchmarkChallenges: %v", err)
	}
	taskObj, err := m.CreateTaskWithOptions("Aperture", "find flag", db.TaskCreateOptions{Mode: "ctf", ChallengeType: "web", ZeroTouch: true})
	if err != nil {
		t.Fatalf("CreateTaskWithOptions: %v", err)
	}
	tidNum, _ := strconv.ParseInt(taskObj.ID, 10, 64)
	t.Cleanup(func() { _, _ = m.DeleteTask(taskObj.ID, DeleteTaskOptions{}) })
	_ = m.pg.BindBenchmarkChallengeTask(t.Context(), sess.ID, "Aperture", tidNum)

	td := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	s := New(ctx, m, td, td, td)
	rt, err := s.bench.runtimeFor(sess)
	if err != nil {
		t.Fatalf("runtimeFor: %v", err)
	}
	// Simulate elapsed >= timeout/2 so shouldFetch=true on every tick.
	rt.taskStartAt["Aperture"] = time.Now().Add(-15 * time.Minute)

	for i := 0; i < 10; i++ {
		ch, _ := m.pg.GetBenchmarkChallenge(t.Context(), sess.ID, "Aperture")
		s.bench.checkChallengeTimeoutAndHint(t.Context(), rt, sess, ch, false)
	}
	if hintCalls != 1 {
		t.Fatalf("expected /hint to be called at most once when platform returns null hint, got %d", hintCalls)
	}
	chAfter, _ := m.pg.GetBenchmarkChallenge(t.Context(), sess.ID, "Aperture")
	if chAfter == nil || !chAfter.HintUsed || chAfter.HintContent != "" {
		t.Fatalf("expected hint_used=true with empty hint_content, got %+v", chAfter)
	}
}

func TestHostedBenchmarkFirstPassScreening(t *testing.T) {
	t.Setenv("P3Y_HOSTED_MODE", "1")
	t.Setenv("P3Y_BENCH_FIRST_PASS_TIMEOUT", "")

	sess := &db.BenchmarkSession{
		ID:                  9999,
		HintPolicy:          "stagnant_only",
		PerChallengeTimeout: 5400,
	}
	// 1. Single-flag Attempt 1 uses 1200s (20m) first-pass budget.
	chFirst := &db.BenchmarkChallenge{UniqueCode: "single_1", FlagCount: 1, AttemptCount: 1}
	if dur, fp := effectiveChallengeTimeout(sess, chFirst); !fp || dur != 1200*time.Second {
		t.Fatalf("expected 1200s first-pass budget for Attempt 1 single-flag, got dur=%v fp=%v", dur, fp)
	}
	// 2. Single-flag Attempt 2 uses full 5400s budget.
	chSecond := &db.BenchmarkChallenge{UniqueCode: "single_1", FlagCount: 1, AttemptCount: 2}
	if dur, fp := effectiveChallengeTimeout(sess, chSecond); fp || dur != 5400*time.Second {
		t.Fatalf("expected 5400s full budget for Attempt 2, got dur=%v fp=%v", dur, fp)
	}
	// 3. Multi-flag Attempt 1 is exempt from first-pass cutoff.
	chMulti := &db.BenchmarkChallenge{UniqueCode: "multi_3", FlagCount: 3, AttemptCount: 1}
	if dur, fp := effectiveChallengeTimeout(sess, chMulti); fp || dur != 5400*time.Second {
		t.Fatalf("expected multi-flag challenge to get full 5400s budget on Attempt 1, got dur=%v fp=%v", dur, fp)
	}
	// 4. Explicit P3Y_BENCH_FIRST_PASS_TIMEOUT=0 disables first-pass screening.
	t.Setenv("P3Y_BENCH_FIRST_PASS_TIMEOUT", "0")
	if dur, fp := effectiveChallengeTimeout(sess, chFirst); fp || dur != 5400*time.Second {
		t.Fatalf("expected P3Y_BENCH_FIRST_PASS_TIMEOUT=0 to disable first-pass, got dur=%v fp=%v", dur, fp)
	}

	// 5. Under first-pass screening (600s): untried AttemptCount=0 beats high-value retry,
	//    and first-pass checkChallengeTimeoutAndHint suppresses GetHint while rotating at >600s only when hasWaiting=true.
	t.Setenv("P3Y_BENCH_FIRST_PASS_TIMEOUT", "600")
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping DB check", err)
	}
	t.Cleanup(func() { m.Close() })

	bt, err := m.CreateTaskWithOptions("fp-high-retry", "goal", db.TaskCreateOptions{Mode: "ctf", ChallengeType: "web", ZeroTouch: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.DeleteTask(bt.ID, DeleteTaskOptions{}) })
	btID, _ := strconv.ParseInt(bt.ID, 10, 64)
	for i := 0; i < 4; i++ {
		_, _ = bt.Store.AddNode("fact", map[string]any{"summary": fmt.Sprintf("f%d", i)}, 0, "confirmed", "worker", nil)
	}
	_ = m.SetTaskStatus(bt.ID, "timeout")

	q := pickChallengeQueue([]*db.BenchmarkChallenge{
		{ID: 1, UniqueCode: "high_retry", TotalScore: 1000, AttemptCount: 1, AutoRetryCount: 1, BoundTaskID: &btID},
		{ID: 2, UniqueCode: "untried_new", TotalScore: 200, AttemptCount: 0},
		{ID: 3, UniqueCode: "low_retry", TotalScore: 200, AttemptCount: 1, AutoRetryCount: 1},
	}, m)
	if len(q) != 3 || q[0].UniqueCode != "untried_new" || q[1].UniqueCode != "high_retry" || q[2].UniqueCode != "low_retry" {
		t.Fatalf("expected first-pass order [untried_new, high_retry, low_retry], got [%s, %s, %s]", q[0].UniqueCode, q[1].UniqueCode, q[2].UniqueCode)
	}

	hintCalls := 0
	mockTSec := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/openapi/v1/challenges/hint" {
			hintCalls++
			_, _ = w.Write([]byte(`{"unique_code":"fp_ch","hint":"some hint"}`))
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer mockTSec.Close()

	dbSess, err := m.pg.CreateBenchmarkSession(t.Context(), db.BenchmarkSessionCreate{
		Name: "fp-test", Provider: "tsecbench", BaseURL: mockTSec.URL, Token: "tok-fp",
		MaxConcurrent: 1, HintPolicy: "stagnant_only", PerChallengeTimeout: 5400,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.pg.Exec(`DELETE FROM benchmark_sessions WHERE id=$1`, dbSess.ID) })
	_ = m.pg.SyncBenchmarkChallenges(t.Context(), dbSess.ID, []db.BenchmarkChallengeUpsert{{
		UniqueCode: "fp_ch", Title: "fp_ch", Category: "web", TotalScore: 300, FlagCount: 1,
	}})
	fpTask, _ := m.CreateTaskWithOptions("fp_ch", "goal", db.TaskCreateOptions{Mode: "ctf", ChallengeType: "web", ZeroTouch: true})
	t.Cleanup(func() { _, _ = m.DeleteTask(fpTask.ID, DeleteTaskOptions{}) })
	fpTID, _ := strconv.ParseInt(fpTask.ID, 10, 64)
	_ = m.pg.BindBenchmarkChallengeTask(t.Context(), dbSess.ID, "fp_ch", fpTID)

	td := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	s := New(ctx, m, td, td, td)
	rt, _ := s.bench.runtimeFor(dbSess)
	// At 7m (>600s/2): still in first-pass -> must NOT call GetHint and must NOT rotate.
	rt.taskStartAt["fp_ch"] = time.Now().Add(-7 * time.Minute)
	chLive, _ := m.pg.GetBenchmarkChallenge(t.Context(), dbSess.ID, "fp_ch")
	if rotated := s.bench.checkChallengeTimeoutAndHint(t.Context(), rt, dbSess, chLive, true); rotated {
		t.Fatal("must not rotate before 10m first-pass budget")
	}
	if hintCalls != 0 {
		t.Fatalf("must not fetch hint during first-pass screening, got %d calls", hintCalls)
	}
	// At 11m (>600s) with hasWaiting=false -> must NOT rotate when queue is empty!
	rt.taskStartAt["fp_ch"] = time.Now().Add(-11 * time.Minute)
	if rotated := s.bench.checkChallengeTimeoutAndHint(t.Context(), rt, dbSess, chLive, false); rotated {
		t.Fatal("must not rotate at 11m when no other challenges are waiting")
	}
	// At 11m (>600s) with hasWaiting=true -> MUST rotate to let untried challenges run!
	if rotated := s.bench.checkChallengeTimeoutAndHint(t.Context(), rt, dbSess, chLive, true); !rotated {
		t.Fatal("expected first-pass rotation at 11m when waiting challenges exist")
	}

	// 6. Momentum Grace Window (+600s) & active benchmark_request_hint 8m anti-laziness gate:
	_ = m.pg.SyncBenchmarkChallenges(t.Context(), dbSess.ID, []db.BenchmarkChallengeUpsert{{
		UniqueCode: "grace_ch", Title: "grace_ch", Category: "pwn", TotalScore: 500, FlagCount: 1,
	}})
	graceTask, _ := m.CreateTaskWithOptions("grace_ch", "goal", db.TaskCreateOptions{Mode: "ctf", ChallengeType: "pwn", ZeroTouch: true})
	t.Cleanup(func() { _, _ = m.DeleteTask(graceTask.ID, DeleteTaskOptions{}) })
	graceTID, _ := strconv.ParseInt(graceTask.ID, 10, 64)
	_ = m.pg.BindBenchmarkChallengeTask(t.Context(), dbSess.ID, "grace_ch", graceTID)

	// (a) Active Hint request before 8m (at 3m) without stagnation must be rejected by the 8m gate.
	rt.taskStartAt["grace_ch"] = time.Now().Add(-3 * time.Minute)
	hintMsg, handled, herr := s.bench.handleRequestHint(t.Context(), graceTID, "trying early hint")
	if herr != nil || !handled || !strings.Contains(hintMsg, "Hint 门禁拦截") || hintCalls != 0 {
		t.Fatalf("expected 8m gate rejection without calling platform /hint, got msg=%q handled=%v err=%v calls=%d", hintMsg, handled, herr, hintCalls)
	}

	// (b) Record a fresh confirmed Fact (active solving momentum) and advance clock to 11m (>600s first-pass):
	//     checkChallengeTimeoutAndHint must grant +600s Momentum Grace instead of rotating!
	_, _ = graceTask.Store.AddNode("fact", map[string]any{"summary": "leaked libc base 0x7f..."}, 0, "confirmed", "worker", nil)
	rt.taskStartAt["grace_ch"] = time.Now().Add(-11 * time.Minute)
	chGrace, _ := m.pg.GetBenchmarkChallenge(t.Context(), dbSess.ID, "grace_ch")
	if rotated := s.bench.checkChallengeTimeoutAndHint(t.Context(), rt, dbSess, chGrace, true); rotated {
		t.Fatal("expected Momentum Grace Window (+600s) to prevent rotation when recent fact exists")
	}
	if !rt.momentumGraceGranted["grace_ch"] {
		t.Fatal("expected momentumGraceGranted[grace_ch]=true")
	}

	// (c) Active Hint request at 11m (>=8m) must succeed and write Hint Fact into graph, and second call must hit cache.
	hintMsg2, handled2, herr2 := s.bench.handleRequestHint(t.Context(), graceTID, "stuck on gadget after 11m")
	if herr2 != nil || !handled2 || !strings.Contains(hintMsg2, "some hint") || hintCalls != 1 {
		t.Fatalf("expected active hint fetch after 8m to succeed, got msg=%q handled=%v err=%v calls=%d", hintMsg2, handled2, herr2, hintCalls)
	}
	hintMsg3, _, _ := s.bench.handleRequestHint(t.Context(), graceTID, "second call")
	if !strings.Contains(hintMsg3, "已缓存") || hintCalls != 1 {
		t.Fatalf("expected second hint request to hit cache without extra platform call, got msg=%q calls=%d", hintMsg3, hintCalls)
	}
}
