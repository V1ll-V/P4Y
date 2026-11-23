package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"p3y/agent"
	"p3y/artifacts"
	"p3y/benchmark"
	"p3y/ctf"
	"p3y/db"
	actool "github.com/Autumn-27/norma/tool"
)

type benchSessionRuntime struct {
	sessionID        int64
	prov             benchmark.Provider
	cfg              benchmark.SessionConfig
	cancel           context.CancelFunc
	cooldownUntil    time.Time
	lastReclaimAt    time.Time
	lastEnvWaitLogAt time.Time
	platformEnvCap   int
	extraTools       []actool.CoreTool
	toolsLoaded      bool
	lastEnvPoll          map[string]time.Time
	taskStartAt          map[string]time.Time
	lastFlagAt           map[string]time.Time
	lastHintAttempt      map[string]time.Time
	momentumGraceGranted map[string]bool
	startingCodes        map[string]bool
	singleWatch          map[string]context.CancelFunc
}

// BenchmarkManager orchestrates unattended zero-touch multi-platform benchmark
// sessions (TSecBench REST, CTF2/DASCTF MCP, and Generic MCP + Skill.zip).
type BenchmarkManager struct {
	s    *Server
	mu   sync.Mutex
	runs map[int64]*benchSessionRuntime
}

func newBenchmarkManager(s *Server) *BenchmarkManager {
	return &BenchmarkManager{
		s:    s,
		runs: map[int64]*benchSessionRuntime{},
	}
}

func (s *Server) registerBenchmarkHooks() {
	if s.bench == nil {
		s.bench = newBenchmarkManager(s)
	}
	ctf.BenchmarkFlagHook = s.bench.handleFlagCandidate
	agent.BenchmarkChoiceHook = s.bench.handleChoice
	agent.BenchmarkHintHook = s.bench.handleRequestHint
	agent.BenchmarkExtraToolsHook = s.bench.extraToolsForTask
	agent.BenchmarkContextHook = s.bench.contextForTask
	go s.bench.resumeRunningSessions()
}

func (s *Server) registerBenchmarkRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/benchmarks/test-connection", s.bench.handleTestConnection)
	mux.HandleFunc("POST /api/benchmarks/parse-skill", s.bench.handleParseSkill)
	mux.HandleFunc("GET /api/benchmarks", s.bench.handleListSessions)
	mux.HandleFunc("POST /api/benchmarks", s.bench.handleCreateSession)
	mux.HandleFunc("GET /api/benchmarks/{id}", s.bench.handleGetSession)
	mux.HandleFunc("PATCH /api/benchmarks/{id}", s.bench.handleUpdateSession)
	mux.HandleFunc("POST /api/benchmarks/{id}/start", s.bench.handleStartSession)
	mux.HandleFunc("POST /api/benchmarks/{id}/challenges/{code}/start", s.bench.handleStartChallenge)
	mux.HandleFunc("POST /api/benchmarks/{id}/stop", s.bench.handleStopSession)
	mux.HandleFunc("POST /api/benchmarks/{id}/sync", s.bench.handleSyncSession)
	mux.HandleFunc("POST /api/benchmarks/{id}/retry-failed", s.bench.handleRetryFailed)
	mux.HandleFunc("DELETE /api/benchmarks/{id}", s.bench.handleDeleteSession)
	mux.HandleFunc("GET /api/benchmarks/{id}/export", s.bench.handleExportSession)
}

const (
	maxBenchmarkAutoRetries          = 3
	defaultHostedBenchAutoRetries    = 5
	defaultHostedBenchTimeoutSec     = 5400
	defaultHostedFirstPassTimeoutSec = 1200 // 托管模式首轮预算（20 分钟），给足单会话 Lead-Solver 一气呵成解题窗口
	benchmarkMomentumGraceDuration   = 600 * time.Second
	benchmarkMomentumRecentWindow    = 180 * time.Second
	benchmarkActiveHintMinElapsed    = 8 * time.Minute
)

func isHostedBenchmarkMode() bool {
	return strings.TrimSpace(os.Getenv("P3Y_HOSTED_MODE")) == "1" ||
		strings.TrimSpace(os.Getenv("P3Y_BENCH_EXIT_ON_DONE")) == "1"
}

// benchmarkFirstPassTimeoutSec returns the fast first-pass screening timeout (in seconds)
// for Attempt 1 of single-flag challenges. Hosted mode defaults to 600s (10 min); set
// P3Y_BENCH_FIRST_PASS_TIMEOUT=0 to disable first-pass screening and use full budget immediately.
func benchmarkFirstPassTimeoutSec() int {
	if raw := strings.TrimSpace(os.Getenv("P3Y_BENCH_FIRST_PASS_TIMEOUT")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil {
			if n <= 0 {
				return 0
			}
			return n
		}
	}
	if isHostedBenchmarkMode() {
		return defaultHostedFirstPassTimeoutSec
	}
	return 0
}

// effectiveChallengeTimeout returns the scheduler rotation budget for ch's current attempt
// and reports whether ch is running in a fast first-pass screening window. Multi-flag
// challenges (FlagCount > 1) and partially solved challenges (CorrectFlagCount > 0) are
// exempt from first-pass cutoff so live pivoting sessions are never interrupted early.
func effectiveChallengeTimeout(sess *db.BenchmarkSession, ch *db.BenchmarkChallenge) (time.Duration, bool) {
	if sess == nil || sess.PerChallengeTimeout <= 0 {
		return 0, false
	}
	full := time.Duration(sess.PerChallengeTimeout) * time.Second
	if ch == nil {
		return full, false
	}
	fpSec := benchmarkFirstPassTimeoutSec()
	if fpSec > 0 && fpSec < sess.PerChallengeTimeout && ch.AttemptCount <= 1 && ch.FlagCount <= 1 && ch.CorrectFlagCount == 0 {
		return time.Duration(fpSec) * time.Second, true
	}
	return full, false
}

// benchmarkMaxAutoRetries returns the max auto-retry rounds per challenge
// (-1 means unlimited retries with backoff). Interactive mode defaults to 3;
// non-interactive hosted mode defaults to 5 unless P3Y_BENCH_MAX_RETRIES overrides it.
func benchmarkMaxAutoRetries() int {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv("P3Y_BENCH_MAX_RETRIES")))
	switch raw {
	case "unlimited", "inf", "infinite":
		return -1
	case "":
		if isHostedBenchmarkMode() {
			return defaultHostedBenchAutoRetries
		}
		return maxBenchmarkAutoRetries
	default:
		if n, err := strconv.Atoi(raw); err == nil {
			if n < 0 {
				return -1
			}
			return n
		}
		if isHostedBenchmarkMode() {
			return defaultHostedBenchAutoRetries
		}
		return maxBenchmarkAutoRetries
	}
}

func isBenchmarkExhaustedMsg(msg string) bool {
	return strings.Contains(msg, "等待手动重排") || strings.Contains(msg, "已达重试上限")
}

func isBenchmarkRetryExhausted(ch *db.BenchmarkChallenge, maxRetries int) bool {
	if ch == nil || maxRetries < 0 {
		return false
	}
	return ch.AutoRetryCount >= maxRetries && (ch.LastError != "" || ch.BoundTaskID != nil)
}

func benchmarkRetryCooldown(nextAttempt int) time.Duration {
	switch {
	case nextAttempt <= 1:
		return 30 * time.Second
	case nextAttempt == 2:
		return 60 * time.Second
	case nextAttempt == 3:
		return 120 * time.Second
	default:
		return 180 * time.Second
	}
}

func parseSessionConfig(raw json.RawMessage) benchmark.SessionConfig {
	var cfg benchmark.SessionConfig
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &cfg)
	}
	return cfg
}

func (bm *BenchmarkManager) providerFor(sess *db.BenchmarkSession) (benchmark.Provider, benchmark.SessionConfig, error) {
	cfg := parseSessionConfig(sess.Config)
	prov, err := benchmark.NewProvider(sess.Provider, sess.BaseURL, sess.Token, cfg)
	if err != nil {
		return nil, cfg, err
	}
	return prov, cfg, nil
}

func (bm *BenchmarkManager) runtimeFor(sess *db.BenchmarkSession) (*benchSessionRuntime, error) {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	if rt, ok := bm.runs[sess.ID]; ok && rt != nil {
		return rt, nil
	}
	prov, cfg, err := bm.providerFor(sess)
	if err != nil {
		return nil, err
	}
	rt := &benchSessionRuntime{
		sessionID:            sess.ID,
		prov:                 prov,
		cfg:                  cfg,
		lastEnvPoll:          map[string]time.Time{},
		taskStartAt:          map[string]time.Time{},
		lastFlagAt:           map[string]time.Time{},
		lastHintAttempt:      map[string]time.Time{},
		momentumGraceGranted: map[string]bool{},
		startingCodes:        map[string]bool{},
		singleWatch:          map[string]context.CancelFunc{},
	}
	bm.runs[sess.ID] = rt
	return rt, nil
}

// ---- HTTP Handlers ----

type benchmarkCreatePayload struct {
	Name                string                  `json:"name"`
	Provider            string                  `json:"provider"`
	BaseURL             string                  `json:"base_url"`
	Token               string                  `json:"token"`
	Config              benchmark.SessionConfig `json:"config"`
	MaxConcurrent       int                     `json:"max_concurrent"`
	HintPolicy          string                  `json:"hint_policy"`
	PerChallengeTimeout int                     `json:"per_challenge_timeout"`
	LLMProfileIDs       []int64                 `json:"llm_profile_ids"`
	AutoStart           bool                    `json:"auto_start"`
}

func (bm *BenchmarkManager) handleTestConnection(w http.ResponseWriter, r *http.Request) {
	var req benchmarkCreatePayload
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(&req); err != nil {
		writeErr(w, 400, "请求格式无效")
		return
	}
	prov, err := benchmark.NewProvider(req.Provider, req.BaseURL, req.Token, req.Config)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()

	profile, whoErr := prov.WhoAmI(ctx)
	challenges, listErr := prov.ListChallenges(ctx, req.Config)
	var discovered []string
	if gc, ok := prov.(*benchmark.GenericMCPClient); ok {
		if tools, derr := gc.DiscoverSafeTools(ctx); derr == nil {
			for _, tl := range tools {
				discovered = append(discovered, tl.Name())
			}
		}
	}
	if listErr != nil && whoErr != nil {
		writeErr(w, 502, listErr.Error())
		return
	}
	writeJSON(w, 200, map[string]any{
		"ok":               listErr == nil,
		"provider":         prov.Kind(),
		"profile":          profile,
		"challenge_count":  len(challenges),
		"discovered_tools": discovered,
		"error":            errString(listErr),
	})
}

func (bm *BenchmarkManager) handleParseSkill(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(20 << 20); err != nil {
		writeErr(w, 400, "上传表单无效："+err.Error())
		return
	}
	f, _, err := r.FormFile("file")
	if err != nil {
		writeErr(w, 400, "缺少 file 上传字段")
		return
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, (16<<20)+1))
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	pkg, err := benchmark.ParseSkillZip(raw)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, pkg)
}

func (bm *BenchmarkManager) handleListSessions(w http.ResponseWriter, r *http.Request) {
	list, err := bm.s.m.pg.ListBenchmarkSessions(r.Context())
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	_ = bm.s.m.pg.PopulateBenchmarkSessionTokens(r.Context(), list)
	writeJSON(w, 200, list)
}

func (bm *BenchmarkManager) handleCreateSession(w http.ResponseWriter, r *http.Request) {
	var req benchmarkCreatePayload
	ct := strings.ToLower(r.Header.Get("Content-Type"))
	if strings.Contains(ct, "multipart/form-data") {
		if err := r.ParseMultipartForm(20 << 20); err != nil {
			writeErr(w, 400, "表单解析失败："+err.Error())
			return
		}
		meta := r.FormValue("payload")
		if strings.TrimSpace(meta) == "" {
			writeErr(w, 400, "缺少 payload 字段")
			return
		}
		if err := json.Unmarshal([]byte(meta), &req); err != nil {
			writeErr(w, 400, "payload JSON 无效")
			return
		}
		if f, _, err := r.FormFile("skill_zip"); err == nil {
			defer f.Close()
			raw, _ := io.ReadAll(io.LimitReader(f, (16<<20)+1))
			if pkg, perr := benchmark.ParseSkillZip(raw); perr == nil {
				req.Config.SkillName = pkg.Name
				req.Config.SkillInstructions = pkg.Instructions
			} else {
				writeErr(w, 400, perr.Error())
				return
			}
		}
	} else {
		if err := json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(&req); err != nil {
			writeErr(w, 400, "JSON 格式无效")
			return
		}
	}
	if strings.TrimSpace(req.Name) == "" {
		req.Name = fmt.Sprintf("测评会话 %s", time.Now().Format("01-02 15:04"))
	}
	if _, err := benchmark.NewProvider(req.Provider, req.BaseURL, req.Token, req.Config); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if sanitizedVPN, _, cleanName, verr := prepareTaskVPNForCreate("ctf", req.Config.CTFVPNConfig, req.Config.CTFVPNFilename); verr != nil {
		writeErr(w, 400, verr.Error())
		return
	} else if sanitizedVPN != "" {
		req.Config.CTFVPNConfig = sanitizedVPN
		req.Config.CTFVPNFilename = cleanName
	}
	cfgRaw, _ := json.Marshal(req.Config)
	sess, err := bm.s.m.pg.CreateBenchmarkSession(r.Context(), db.BenchmarkSessionCreate{
		Name:                req.Name,
		Provider:            req.Provider,
		BaseURL:             req.BaseURL,
		Token:               req.Token,
		Config:              cfgRaw,
		MaxConcurrent:       req.MaxConcurrent,
		HintPolicy:          req.HintPolicy,
		PerChallengeTimeout: req.PerChallengeTimeout,
		LLMProfileIDs:       req.LLMProfileIDs,
	})
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	_ = bm.s.m.pg.AppendBenchmarkEvent(r.Context(), sess.ID, "", "session_created",
		fmt.Sprintf("已创建测评会话（平台：%s）", sess.Provider), nil)

	// Best-effort initial sync so UI shows challenge matrix immediately.
	syncCtx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	if _, serr := bm.syncChallenges(syncCtx, sess); serr != nil {
		_ = bm.s.m.pg.AppendBenchmarkEvent(r.Context(), sess.ID, "", "sync_warn", "初始题库同步失败："+serr.Error(), nil)
	}
	cancel()

	if req.AutoStart {
		_ = bm.startSession(sess.ID)
	}
	updated, err := bm.s.m.pg.GetBenchmarkSession(r.Context(), sess.ID)
	if err == nil && updated != nil {
		sess = updated
	}
	writeJSON(w, 201, sess)
}

func (bm *BenchmarkManager) handleGetSession(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "无效的测评会话 ID")
		return
	}
	sess, err := bm.s.m.pg.GetBenchmarkSession(r.Context(), id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if sess == nil {
		writeErr(w, 404, "测评会话不存在")
		return
	}
	challenges, err := bm.s.m.pg.ListBenchmarkChallenges(r.Context(), id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	_ = bm.s.m.pg.PopulateBenchmarkSessionTokens(r.Context(), []*db.BenchmarkSession{sess})
	_ = bm.s.m.pg.PopulateBenchmarkChallengeTokens(r.Context(), id, challenges)
	submissions, _ := bm.s.m.pg.ListBenchmarkSubmissions(r.Context(), id)
	events, _ := bm.s.m.pg.ListBenchmarkEvents(r.Context(), id, 150)
	writeJSON(w, 200, map[string]any{
		"session":     sess,
		"challenges":  challenges,
		"submissions": submissions,
		"events":      events,
	})
}

func (bm *BenchmarkManager) handleStartSession(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "无效的测评会话 ID")
		return
	}
	if err := bm.startSession(id); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	sess, _ := bm.s.m.pg.GetBenchmarkSession(r.Context(), id)
	writeJSON(w, 200, sess)
}

func (bm *BenchmarkManager) handleStartChallenge(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "无效的测评会话 ID")
		return
	}
	code := strings.TrimSpace(r.PathValue("code"))
	if code == "" {
		writeErr(w, 400, "无效的题目标识")
		return
	}
	ctx := r.Context()
	sess, err := bm.s.m.pg.GetBenchmarkSession(ctx, id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if sess == nil {
		writeErr(w, 404, "测评会话不存在")
		return
	}
	ch, err := bm.s.m.pg.GetBenchmarkChallenge(ctx, id, code)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if ch == nil {
		writeErr(w, 404, "题目不存在于该测评会话")
		return
	}
	if ch.IsCompleted {
		writeErr(w, 400, "该题目已完成，无需重复启动")
		return
	}
	if isNoFlagBenchmarkChallenge(ch) {
		writeErr(w, 400, "该题目声明无 Flag，无需启动")
		return
	}
	if ch.BoundTaskID != nil {
		if t, ok := bm.s.m.Task(strconv.FormatInt(*ch.BoundTaskID, 10)); ok && !isTerminalStatus(t.lifecycleSnapshot().Status) {
			writeErr(w, 409, fmt.Sprintf("该题目已在运行中（任务 #%d）", *ch.BoundTaskID))
			return
		}
	}

	rt, err := bm.runtimeFor(sess)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	bm.mu.Lock()
	if rt.startingCodes == nil {
		rt.startingCodes = map[string]bool{}
	}
	if rt.startingCodes[code] {
		bm.mu.Unlock()
		writeErr(w, 409, "该题目正在启动中，请稍候")
		return
	}
	rt.startingCodes[code] = true
	bm.mu.Unlock()
	defer func() {
		bm.mu.Lock()
		delete(rt.startingCodes, code)
		bm.mu.Unlock()
	}()

	// Reset prior failure/retry backoff metadata while preserving history_task_ids memory chain.
	if ch.LastError != "" || ch.NextRetryAt != nil || ch.AutoRetryCount > 0 {
		if rerr := bm.s.m.pg.ResetBenchmarkChallengeForRetry(ctx, id, code); rerr == nil {
			if reloaded, gerr := bm.s.m.pg.GetBenchmarkChallenge(ctx, id, code); gerr == nil && reloaded != nil {
				ch = reloaded
			}
		}
	}

	// Count currently active platform containers so we respect max_concurrent slot limit.
	challenges, err := bm.s.m.pg.ListBenchmarkChallenges(ctx, id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	activeContainers := 0
	for _, c := range challenges {
		if c.UniqueCode == code {
			continue
		}
		if c.ContainerStatus == "available" || c.ContainerStatus == "pending" {
			activeContainers++
		}
	}
	effectiveSlots := sess.MaxConcurrent
	if effectiveSlots <= 0 {
		effectiveSlots = 1
	}

	startCtx, cancel := context.WithTimeout(bm.s.ctx, 90*time.Second)
	defer cancel()
	launched, _, err := bm.startChallengeSlot(startCtx, rt, sess, ch, effectiveSlots, activeContainers)
	if err != nil {
		if errors.Is(err, errBenchmarkQuotaDeferred) {
			writeErr(w, 409, "当前并发容器槽位已满，请先等待或停止其他正在运行的题目")
			return
		}
		_ = bm.s.m.pg.AppendBenchmarkEvent(context.Background(), id, code, "slot_error", err.Error(), nil)
		writeErr(w, 502, err.Error())
		return
	}

	reloaded, _ := bm.s.m.pg.GetBenchmarkChallenge(context.Background(), id, code)
	if reloaded == nil {
		reloaded = ch
	}
	if launched {
		_ = bm.s.m.pg.AppendBenchmarkEvent(context.Background(), id, code, "challenge_single_started",
			fmt.Sprintf("已手动单独启动题目 %s（仅运行此题，不触发整套调度）", reloaded.Title), nil)
		bm.ensureSingleChallengeWatch(id, rt, code)
	}
	writeJSON(w, 200, map[string]any{
		"launched":  launched,
		"challenge": reloaded,
		"task_id":   reloaded.BoundTaskID,
	})
}

// ensureSingleChallengeWatch runs a lightweight per-challenge monitor when a single
// challenge is started manually without the full session scheduler loop, handling
// container TTL renewal, optional stagnant Hint fetching, and container cleanup on exit.
func (bm *BenchmarkManager) ensureSingleChallengeWatch(sessionID int64, rt *benchSessionRuntime, uniqueCode string) {
	bm.mu.Lock()
	if rt.cancel != nil {
		// Full session loop is already active and will monitor this challenge.
		bm.mu.Unlock()
		return
	}
	if rt.singleWatch == nil {
		rt.singleWatch = map[string]context.CancelFunc{}
	}
	if prev, ok := rt.singleWatch[uniqueCode]; ok && prev != nil {
		prev()
	}
	wCtx, wCancel := context.WithCancel(bm.s.ctx)
	rt.singleWatch[uniqueCode] = wCancel
	bm.mu.Unlock()

	go func() {
		defer func() {
			wCancel()
			bm.mu.Lock()
			delete(rt.singleWatch, uniqueCode)
			bm.mu.Unlock()
		}()
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-wCtx.Done():
				return
			case <-ticker.C:
			}
			// If full session loop started later, yield monitoring to it.
			bm.mu.Lock()
			fullRunning := rt.cancel != nil
			bm.mu.Unlock()
			if fullRunning {
				return
			}
			sess, err := bm.s.m.pg.GetBenchmarkSession(wCtx, sessionID)
			if err != nil || sess == nil {
				return
			}
			ch, err := bm.s.m.pg.GetBenchmarkChallenge(wCtx, sessionID, uniqueCode)
			if err != nil || ch == nil {
				return
			}
			if ch.IsCompleted {
				if ch.ContainerStatus == "available" || ch.ContainerStatus == "pending" {
					_ = rt.prov.CloseEnvironment(wCtx, uniqueCode)
					_ = bm.s.m.pg.UpdateBenchmarkChallengeEnv(wCtx, sessionID, uniqueCode, "stopped", nil, nil, "")
				}
				return
			}
			boundRunning := false
			if ch.BoundTaskID != nil {
				if t, ok := bm.s.m.Task(strconv.FormatInt(*ch.BoundTaskID, 10)); ok && !isTerminalStatus(t.lifecycleSnapshot().Status) {
					boundRunning = true
				}
			}
			if !boundRunning {
				if ch.ContainerStatus == "available" || ch.ContainerStatus == "pending" {
					_ = rt.prov.CloseEnvironment(wCtx, uniqueCode)
					_ = bm.s.m.pg.UpdateBenchmarkChallengeEnv(wCtx, sessionID, uniqueCode, "stopped", nil, nil, "")
				}
				return
			}
			if ch.ContainerStatus == "available" || ch.ContainerStatus == "pending" {
				bm.refreshActiveEnv(wCtx, rt, sess, ch)
			}
			bm.checkChallengeTimeoutAndHint(wCtx, rt, sess, ch, false)
		}
	}()
}

func (bm *BenchmarkManager) handleStopSession(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "无效的测评会话 ID")
		return
	}
	bm.stopSession(id, "stopped", "用户手动停止测评")
	sess, _ := bm.s.m.pg.GetBenchmarkSession(r.Context(), id)
	writeJSON(w, 200, sess)
}

func (bm *BenchmarkManager) handleSyncSession(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "无效的测评会话 ID")
		return
	}
	sess, err := bm.s.m.pg.GetBenchmarkSession(r.Context(), id)
	if err != nil || sess == nil {
		writeErr(w, 404, "测评会话不存在")
		return
	}
	n, err := bm.syncChallenges(r.Context(), sess)
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	_ = bm.s.m.pg.ClearBenchmarkTransientErrors(r.Context(), id)
	sess, _ = bm.s.m.pg.GetBenchmarkSession(r.Context(), id)
	writeJSON(w, 200, map[string]any{"synced": n, "session": sess})
}

func (bm *BenchmarkManager) handleRetryFailed(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "无效的测评会话 ID")
		return
	}
	sess, err := bm.s.m.pg.GetBenchmarkSession(r.Context(), id)
	if err != nil || sess == nil {
		writeErr(w, 404, "测评会话不存在")
		return
	}
	resetCount, err := bm.s.m.pg.ResetFailedBenchmarkChallenges(r.Context(), id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if resetCount > 0 {
		_ = bm.s.m.pg.AppendBenchmarkEvent(r.Context(), id, "", "retry_queued",
			fmt.Sprintf("已将 %d 道中断/失败题目重置回优先待调度队列", resetCount), nil)
	}
	sess, _ = bm.s.m.pg.GetBenchmarkSession(r.Context(), id)
	writeJSON(w, 200, map[string]any{"reset": resetCount, "session": sess})
}

func (bm *BenchmarkManager) handleUpdateSession(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "无效的测评会话 ID")
		return
	}
	var req struct {
		MaxConcurrent       int `json:"max_concurrent"`
		PerChallengeTimeout int `json:"per_challenge_timeout"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeErr(w, 400, "JSON 格式无效")
		return
	}
	sess, err := bm.s.m.pg.GetBenchmarkSession(r.Context(), id)
	if err != nil || sess == nil {
		writeErr(w, 404, "测评会话不存在")
		return
	}
	if req.MaxConcurrent <= 0 && req.PerChallengeTimeout <= 0 {
		writeErr(w, 400, "请提供有效的并发槽位或单题预算时间")
		return
	}
	if err := bm.s.m.pg.UpdateBenchmarkSessionSettings(r.Context(), id, req.MaxConcurrent, req.PerChallengeTimeout); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	updated, _ := bm.s.m.pg.GetBenchmarkSession(r.Context(), id)
	if updated != nil {
		_ = bm.s.m.pg.AppendBenchmarkEvent(r.Context(), id, "", "session_updated",
			fmt.Sprintf("已更新测评参数：并发槽位 %d，单题预算 %ds（%d 分钟）",
				updated.MaxConcurrent, updated.PerChallengeTimeout, updated.PerChallengeTimeout/60), nil)
	}
	writeJSON(w, 200, updated)
}

func (bm *BenchmarkManager) scheduleChallengeAutoRetry(ctx context.Context, sessionID int64, ch *db.BenchmarkChallenge, reason string) {
	if ch == nil || ch.IsCompleted {
		return
	}
	cleanReason := strings.TrimSpace(reason)
	if cleanReason == "" {
		cleanReason = "执行异常"
	}
	maxRetries := benchmarkMaxAutoRetries()
	if maxRetries >= 0 && ch.AutoRetryCount >= maxRetries {
		msg := fmt.Sprintf("%s（已自动重试 %d 次仍异常，等待手动重排）", cleanReason, maxRetries)
		if isHostedBenchmarkMode() {
			msg = fmt.Sprintf("%s（已自动尝试 %d 次仍未完成，已达重试上限并让出调度队列）", cleanReason, maxRetries)
		}
		_ = bm.s.m.pg.ScheduleBenchmarkChallengeRetry(ctx, sessionID, ch.UniqueCode, nil, ch.AutoRetryCount, msg)
		ch.NextRetryAt = nil
		ch.LastError = msg
		_ = bm.s.m.pg.AppendBenchmarkEvent(ctx, sessionID, ch.UniqueCode, "challenge_retry_exhausted",
			fmt.Sprintf("题目 %s %s", ch.UniqueCode, msg), nil)
		return
	}
	nextAttempt := ch.AutoRetryCount + 1
	cooldown := benchmarkRetryCooldown(nextAttempt)
	retryAt := time.Now().Add(cooldown)
	limitLabel := "∞"
	if maxRetries >= 0 {
		limitLabel = strconv.Itoa(maxRetries)
	}
	msg := fmt.Sprintf("%s（冷却 %ds 后自动重排重试 %d/%s）", cleanReason, int(cooldown.Seconds()), nextAttempt, limitLabel)
	if err := bm.s.m.pg.ScheduleBenchmarkChallengeRetry(ctx, sessionID, ch.UniqueCode, &retryAt, nextAttempt, msg); err == nil {
		ch.NextRetryAt = &retryAt
		ch.AutoRetryCount = nextAttempt
		ch.LastError = msg
		_ = bm.s.m.pg.AppendBenchmarkEvent(ctx, sessionID, ch.UniqueCode, "challenge_auto_retry_scheduled",
			fmt.Sprintf("题目 %s %s", ch.UniqueCode, msg), nil)
	}
}

func (bm *BenchmarkManager) resumeRunningSessions() {
	if bm == nil || bm.s == nil || bm.s.m == nil || bm.s.m.pg == nil || bm.s.ctx == nil {
		return
	}
	sessions, err := bm.s.m.pg.ListBenchmarkSessions(bm.s.ctx)
	if err != nil {
		return
	}
	for _, sess := range sessions {
		if sess != nil && sess.Status == "running" {
			_ = bm.startSession(sess.ID)
		}
	}
	bm.autoBootstrapFromEnv(sessions)
}

func (bm *BenchmarkManager) autoBootstrapFromEnv(existing []*db.BenchmarkSession) {
	baseURL := strings.TrimSpace(os.Getenv("BENCHMARK_BASE_URL"))
	token := strings.TrimSpace(os.Getenv("BENCHMARK_TOKEN"))
	if baseURL == "" || token == "" {
		return
	}
	for _, sess := range existing {
		if sess != nil && strings.TrimSpace(sess.BaseURL) == baseURL && strings.TrimSpace(sess.Token) == token {
			if sess.Status == "idle" || sess.Status == "paused" {
				_ = bm.startSession(sess.ID)
			}
			return
		}
	}

	prov := strings.TrimSpace(os.Getenv("P3Y_BENCH_PROVIDER"))
	if prov == "" {
		prov = "tsecbench"
	}
	name := strings.TrimSpace(os.Getenv("P3Y_BENCH_NAME"))
	if name == "" {
		name = "hosted-" + prov
	}
	maxConc, _ := strconv.Atoi(strings.TrimSpace(os.Getenv("P3Y_BENCH_MAX_CONCURRENT")))
	if maxConc <= 0 && strings.EqualFold(prov, "tsecbench") {
		maxConc = 3
	}
	timeoutSec, _ := strconv.Atoi(strings.TrimSpace(os.Getenv("P3Y_BENCH_CHALLENGE_TIMEOUT")))
	if timeoutSec <= 0 {
		timeoutSec = defaultHostedBenchTimeoutSec
	}
	hintPolicy := strings.TrimSpace(os.Getenv("P3Y_BENCH_HINT_POLICY"))
	if hintPolicy == "" {
		hintPolicy = "stagnant_only"
	}
	var cfg benchmark.SessionConfig
	cfgRaw, _ := json.Marshal(cfg)

	sess, err := bm.s.m.pg.CreateBenchmarkSession(bm.s.ctx, db.BenchmarkSessionCreate{
		Name:                name,
		Provider:            prov,
		BaseURL:             baseURL,
		Token:               token,
		Config:              cfgRaw,
		MaxConcurrent:       maxConc,
		HintPolicy:          hintPolicy,
		PerChallengeTimeout: timeoutSec,
	})
	if err != nil {
		log.Printf("[BENCH] auto-bootstrap session create failed: %v", err)
		return
	}
	_ = bm.s.m.pg.AppendBenchmarkEvent(bm.s.ctx, sess.ID, "", "session_created",
		fmt.Sprintf("已从环境变量自动创建测评会话（平台：%s，并发：%d，单题超时：%ds）", sess.Provider, sess.MaxConcurrent, sess.PerChallengeTimeout), nil)

	syncCtx, cancel := context.WithTimeout(bm.s.ctx, 20*time.Second)
	if _, serr := bm.syncChallenges(syncCtx, sess); serr != nil {
		_ = bm.s.m.pg.AppendBenchmarkEvent(bm.s.ctx, sess.ID, "", "sync_warn", "初始题库同步失败："+serr.Error(), nil)
	}
	cancel()

	if err := bm.startSession(sess.ID); err != nil {
		log.Printf("[BENCH] auto-bootstrap start failed: %v", err)
		return
	}
	log.Printf("[BENCH] auto-started hosted benchmark session #%d (%s)", sess.ID, sess.Provider)
}

func (bm *BenchmarkManager) handleDeleteSession(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "无效的测评会话 ID")
		return
	}
	bm.stopSession(id, "stopped", "删除测评会话")
	taskIDs, _ := bm.s.m.pg.ListBenchmarkChallengeTaskIDs(r.Context(), id)
	deletedTasks := 0
	failedTasks := 0
	for _, tid := range taskIDs {
		tidStr := strconv.FormatInt(tid, 10)
		_, statusCode, delErr := bm.s.deleteTaskInternal(r.Context(), tidStr, DeleteTaskOptions{
			DeleteFiles:      true,
			DeleteLLMRecords: true,
		})
		if delErr != nil {
			if statusCode == http.StatusOK {
				deletedTasks++
				log.Printf("[BENCH] delete session #%d task #%d partial cleanup warning: %v", id, tid, delErr)
			} else {
				failedTasks++
				log.Printf("[BENCH] delete session #%d task #%d failed (%d): %v", id, tid, statusCode, delErr)
			}
			continue
		}
		deletedTasks++
	}
	bm.mu.Lock()
	delete(bm.runs, id)
	bm.mu.Unlock()
	if err := bm.s.m.pg.DeleteBenchmarkSession(r.Context(), id); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{
		"deleted":       true,
		"id":            id,
		"deleted_tasks": deletedTasks,
		"failed_tasks":  failedTasks,
	})
}

func (bm *BenchmarkManager) handleExportSession(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "无效的测评会话 ID")
		return
	}
	sess, err := bm.s.m.pg.GetBenchmarkSession(r.Context(), id)
	if err != nil || sess == nil {
		writeErr(w, 404, "测评会话不存在")
		return
	}
	challenges, _ := bm.s.m.pg.ListBenchmarkChallenges(r.Context(), id)
	_ = bm.s.m.pg.PopulateBenchmarkSessionTokens(r.Context(), []*db.BenchmarkSession{sess})
	_ = bm.s.m.pg.PopulateBenchmarkChallengeTokens(r.Context(), id, challenges)
	submissions, _ := bm.s.m.pg.ListBenchmarkSubmissions(r.Context(), id)
	events, _ := bm.s.m.pg.ListBenchmarkEvents(r.Context(), id, 500)
	payload := map[string]any{
		"exported_at": time.Now().UTC(),
		"session":     sess,
		"challenges":  challenges,
		"submissions": submissions,
		"events":      events,
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="benchmark-%d.json"`, id))
	writeJSON(w, 200, payload)
}

// ---- Orchestration ----

func (bm *BenchmarkManager) syncChallenges(ctx context.Context, sess *db.BenchmarkSession) (int, error) {
	rt, err := bm.runtimeFor(sess)
	if err != nil {
		return 0, err
	}
	specs, err := rt.prov.ListChallenges(ctx, rt.cfg)
	if err != nil {
		return 0, err
	}
	upserts := make([]db.BenchmarkChallengeUpsert, 0, len(specs))
	for _, c := range specs {
		upserts = append(upserts, db.BenchmarkChallengeUpsert{
			UniqueCode:       c.UniqueCode,
			Title:            c.Title,
			Description:      c.Description,
			Category:         c.Category,
			Difficulty:       c.Difficulty,
			Level:            c.Level,
			SubmissionType:   c.SubmissionType,
			TotalScore:       c.TotalScore,
			CumulativeScore:  c.CumulativeScore,
			FlagCount:        c.FlagCount,
			CorrectFlagCount: c.CorrectFlagCount,
			IsCompleted:      c.IsCompleted,
			ContainerStatus:  c.ContainerStatus,
			ContainerAddr:    c.ContainerAddr,
			Meta:             benchmark.ChallengeMetaJSON(c),
		})
	}
	if err := bm.s.m.pg.SyncBenchmarkChallenges(ctx, sess.ID, upserts); err != nil {
		return 0, err
	}
	return len(upserts), nil
}

func (bm *BenchmarkManager) startSession(sessionID int64) error {
	sess, err := bm.s.m.pg.GetBenchmarkSession(context.Background(), sessionID)
	if err != nil {
		return err
	}
	if sess == nil {
		return errors.New("测评会话不存在")
	}
	rt, err := bm.runtimeFor(sess)
	if err != nil {
		return err
	}
	bm.mu.Lock()
	if rt.cancel != nil {
		rt.cancel()
	}
	ctx, cancel := context.WithCancel(bm.s.ctx)
	rt.cancel = cancel
	bm.mu.Unlock()

	if err := bm.s.m.pg.UpdateBenchmarkSessionStatus(context.Background(), sessionID, "running", ""); err != nil {
		cancel()
		return err
	}
	_ = bm.s.m.pg.AppendBenchmarkEvent(context.Background(), sessionID, "", "session_started", "开始零交互自动测评", nil)
	go bm.runSessionLoop(ctx, sessionID, rt)
	return nil
}

func isRemoteSessionTerminatedError(err error) bool {
	var se *benchmark.StructuredError
	if !errors.As(err, &se) {
		return false
	}
	if se.HTTPStatus == 401 || se.Code == "ENDED" || se.Code == "EXPIRED" {
		return true
	}
	return se.HTTPStatus == 409 && strings.Contains(strings.ToLower(se.Message), "already finished")
}

func (bm *BenchmarkManager) stopSession(sessionID int64, terminalStatus, reason string) {
	bm.mu.Lock()
	rt := bm.runs[sessionID]
	if rt != nil {
		if rt.cancel != nil {
			rt.cancel()
			rt.cancel = nil
		}
		for code, wCancel := range rt.singleWatch {
			if wCancel != nil {
				wCancel()
			}
			delete(rt.singleWatch, code)
		}
	}
	bm.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	sess, _ := bm.s.m.pg.GetBenchmarkSession(ctx, sessionID)
	if sess != nil {
		if rt == nil {
			rt, _ = bm.runtimeFor(sess)
		}
		if rt != nil {
			challenges, _ := bm.s.m.pg.ListBenchmarkChallenges(ctx, sessionID)
			for _, ch := range challenges {
				if ch.ContainerStatus == "available" || ch.ContainerStatus == "pending" {
					_ = rt.prov.CloseEnvironment(ctx, ch.UniqueCode)
					_ = bm.s.m.pg.UpdateBenchmarkChallengeEnv(ctx, sessionID, ch.UniqueCode, "stopped", nil, nil, "")
				}
				if ch.BoundTaskID != nil {
					taskID := strconv.FormatInt(*ch.BoundTaskID, 10)
					wasRunning := false
					if t, ok := bm.s.m.Task(taskID); ok && !isTerminalStatus(t.lifecycleSnapshot().Status) {
						wasRunning = true
					}
					bm.stopBoundTask(taskID, "failed", errors.New(reason))
					if wasRunning && !ch.IsCompleted {
						_ = bm.s.m.pg.ResetBenchmarkChallengeForRetry(ctx, sessionID, ch.UniqueCode)
					}
				}
			}
		}
		_ = bm.s.m.pg.UpdateBenchmarkSessionStatus(ctx, sessionID, terminalStatus, "")
		_ = bm.s.m.pg.AppendBenchmarkEvent(ctx, sessionID, "", "session_stopped", reason, nil)
	}
}

func (bm *BenchmarkManager) stopBoundTask(taskID, terminalStatus string, cause error) {
	if t, ok := bm.s.m.Task(taskID); ok {
		if !isTerminalStatus(t.lifecycleSnapshot().Status) {
			_ = bm.s.m.SetTaskStatus(taskID, terminalStatus)
		}
		bm.s.engine.cancelExec(taskID, cause)
		t.Notify()
	}
}

func (bm *BenchmarkManager) runSessionLoop(ctx context.Context, sessionID int64, rt *benchSessionRuntime) {
	defer func() {
		if bm != nil && bm.s != nil && bm.s.ctx != nil && bm.s.ctx.Err() == nil && os.Getenv("P3Y_BENCH_EXIT_ON_DONE") == "1" {
			bm.s.notifyBenchmarkDone()
		}
	}()
	sess, err := bm.s.m.pg.GetBenchmarkSession(ctx, sessionID)
	if err != nil || sess == nil {
		return
	}
	effectiveSlots := sess.MaxConcurrent
	activeRemoteEnvs := 0
	if prof, werr := rt.prov.WhoAmI(ctx); werr == nil && prof != nil {
		if prof.MaxEnvironments > 0 && prof.MaxEnvironments < effectiveSlots {
			effectiveSlots = prof.MaxEnvironments
		}
		activeRemoteEnvs = prof.ActiveEnvironments
		_ = bm.s.m.pg.AppendBenchmarkEvent(ctx, sessionID, "", "whoami",
			fmt.Sprintf("平台凭证校验成功（并发环境配额=%d，平台当前占用=%d）", prof.MaxEnvironments, prof.ActiveEnvironments), prof)
	} else if werr != nil {
		_ = bm.s.m.pg.AppendBenchmarkEvent(ctx, sessionID, "", "whoami_warn", "获取平台配额信息失败："+werr.Error(), nil)
	}
	_ = bm.s.m.pg.ClearBenchmarkTransientErrors(ctx, sessionID)
	if _, serr := bm.syncChallenges(ctx, sess); serr != nil {
		if isRemoteSessionTerminatedError(serr) {
			_ = bm.s.m.pg.UpdateBenchmarkSessionStatus(context.Background(), sessionID, "expired", serr.Error())
			_ = bm.s.m.pg.AppendBenchmarkEvent(context.Background(), sessionID, "", "session_expired", serr.Error(), nil)
			return
		}
		_ = bm.s.m.pg.UpdateBenchmarkSessionStatus(context.Background(), sessionID, "failed", serr.Error())
		_ = bm.s.m.pg.AppendBenchmarkEvent(context.Background(), sessionID, "", "error", "同步题目列表失败："+serr.Error(), nil)
		return
	}
	if activeRemoteEnvs > 0 {
		if existing, lerr := bm.s.m.pg.ListBenchmarkChallenges(ctx, sessionID); lerr == nil {
			bm.reclaimOrphanedEnvironments(ctx, rt, sess, existing)
		}
	}

	ticker := time.NewTicker(4 * time.Second)
	defer ticker.Stop()

	for {
		if err := bm.tickSession(ctx, sessionID, rt, effectiveSlots); err != nil {
			if ctx.Err() != nil {
				return
			}
			if isRemoteSessionTerminatedError(err) {
				_ = bm.s.m.pg.UpdateBenchmarkSessionStatus(context.Background(), sessionID, "expired", err.Error())
				_ = bm.s.m.pg.AppendBenchmarkEvent(context.Background(), sessionID, "", "session_expired", err.Error(), nil)
				return
			}
			_ = bm.s.m.pg.AppendBenchmarkEvent(context.Background(), sessionID, "", "tick_warn", err.Error(), nil)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (bm *BenchmarkManager) tickSession(ctx context.Context, sessionID int64, rt *benchSessionRuntime, effectiveSlots int) error {
	sess, err := bm.s.m.pg.GetBenchmarkSession(ctx, sessionID)
	if err != nil || sess == nil || sess.Status != "running" {
		return context.Canceled
	}
	if effectiveSlots <= 0 {
		effectiveSlots = 1
	}
	if rt != nil && rt.platformEnvCap > 0 && rt.platformEnvCap < effectiveSlots {
		effectiveSlots = rt.platformEnvCap
	}
	if rt != nil && time.Now().Before(rt.cooldownUntil) {
		return nil
	}

	challenges, err := bm.s.m.pg.ListBenchmarkChallenges(ctx, sessionID)
	if err != nil {
		return err
	}
	unsolved := make([]*db.BenchmarkChallenge, 0, len(challenges))
	runningList := make([]*db.BenchmarkChallenge, 0, len(challenges))
	activeContainers := 0
	activeTasks := 0

	for _, ch := range challenges {
		hasContainer := ch.ContainerStatus == "available" || ch.ContainerStatus == "pending"

		var boundRunning bool
		if ch.BoundTaskID != nil {
			t, ok := bm.s.m.Task(strconv.FormatInt(*ch.BoundTaskID, 10))
			if ok && !isTerminalStatus(t.lifecycleSnapshot().Status) {
				boundRunning = true
				activeTasks++
			}
		}

		// Recover incomplete challenges that previously terminated before receiving a
		// challenge description (or had no detail synced) so they re-enter the front
		// of the queue to fetch fresh detail and container/attachments properly.
		if !ch.IsCompleted && ch.BoundTaskID != nil && !boundRunning && strings.TrimSpace(ch.Description) == "" {
			if rerr := bm.s.m.pg.ResetBenchmarkChallengeForRetry(ctx, sessionID, ch.UniqueCode); rerr == nil {
				ch.BoundTaskID = nil
				ch.BoundTaskStatus = ""
				ch.AttemptCount = 0
				ch.AutoRetryCount = 0
				ch.NextRetryAt = nil
				ch.LastError = ""
				ch.ContainerStatus = "stopped"
				ch.ContainerAddr = nil
				hasContainer = false
			}
		}

		// Cleanup stray containers for already-solved or finished/idle challenges so
		// platform environment quota is released immediately.
		if hasContainer && (ch.IsCompleted || !boundRunning) {
			_ = rt.prov.CloseEnvironment(ctx, ch.UniqueCode)
			keepErr := ""
			if !ch.IsCompleted {
				keepErr = ch.LastError
			}
			_ = bm.s.m.pg.UpdateBenchmarkChallengeEnv(ctx, sessionID, ch.UniqueCode, "stopped", nil, nil, keepErr)
			hasContainer = false
		}
		if ch.IsCompleted {
			continue
		}

		// Check cooldown auto-requeue or schedule cooldown for newly terminated failed/timed-out tasks.
		maxRetries := benchmarkMaxAutoRetries()
		if !boundRunning {
			if ch.NextRetryAt != nil {
				if !time.Now().Before(*ch.NextRetryAt) {
					if rerr := bm.s.m.pg.RequeueBenchmarkChallengeFromCooldown(ctx, sessionID, ch.UniqueCode); rerr == nil {
						ch.BoundTaskID = nil
						ch.BoundTaskStatus = ""
						ch.LastError = ""
						ch.NextRetryAt = nil
						ch.ContainerStatus = "stopped"
						ch.ContainerAddr = nil
						limitLabel := "∞"
						if maxRetries >= 0 {
							limitLabel = strconv.Itoa(maxRetries)
						}
						_ = bm.s.m.pg.AppendBenchmarkEvent(ctx, sessionID, ch.UniqueCode, "challenge_auto_requeued",
							fmt.Sprintf("冷却结束，题目 %s 已自动重新进入待调度队列（第 %d/%s 次重试，将继承前序探索记忆）",
								ch.UniqueCode, ch.AutoRetryCount, limitLabel), nil)
					}
				}
			} else if ch.BoundTaskID != nil {
				if maxRetries < 0 || ch.AutoRetryCount < maxRetries || !isBenchmarkExhaustedMsg(ch.LastError) {
					statusTag := ch.BoundTaskStatus
					if statusTag == "" {
						statusTag = "terminated"
					}
					bm.scheduleChallengeAutoRetry(ctx, sessionID, ch, "前序任务状态为 "+statusTag)
				}
			}
		}

		unsolved = append(unsolved, ch)

		if hasContainer {
			activeContainers++
			bm.refreshActiveEnv(ctx, rt, sess, ch)
		}
		if boundRunning {
			runningList = append(runningList, ch)
		}
	}

	maxRetries := benchmarkMaxAutoRetries()
	waitingCount := 0
	for _, ch := range unsolved {
		if isNoFlagBenchmarkChallenge(ch) {
			continue
		}
		if ch.BoundTaskID != nil {
			if t, ok := bm.s.m.Task(strconv.FormatInt(*ch.BoundTaskID, 10)); ok && !isTerminalStatus(t.lifecycleSnapshot().Status) {
				continue
			}
		}
		if isBenchmarkRetryExhausted(ch, maxRetries) {
			continue
		}
		waitingCount++
	}
	hasWaiting := waitingCount > 0
	for _, ch := range runningList {
		if bm.checkChallengeTimeoutAndHint(ctx, rt, sess, ch, hasWaiting) {
			if activeTasks > 0 {
				activeTasks--
			}
			if activeContainers > 0 && challengeHasContainer(sess.Provider, ch) {
				activeContainers--
			}
		}
	}

	if len(unsolved) == 0 || (isHostedBenchmarkMode() && activeTasks == 0 && waitingCount == 0) {
		summary := fmt.Sprintf("全部 %d 道题目已完成，最终得分 %d/%d", sess.TotalCount, sess.TotalScore, sess.MaxPossibleScore)
		if len(unsolved) > 0 {
			summary = fmt.Sprintf("无等待人力重排，托管测评自动收口（已解题 %d/%d，%d 道达到自动重试上限，最终得分 %d/%d）",
				sess.CompletedCount, sess.TotalCount, len(unsolved), sess.TotalScore, sess.MaxPossibleScore)
		}
		_ = bm.s.m.pg.UpdateBenchmarkSessionStatus(ctx, sessionID, "completed", "")
		_ = bm.s.m.pg.AppendBenchmarkEvent(ctx, sessionID, "", "session_completed", summary, nil)
		bm.mu.Lock()
		if rt.cancel != nil {
			rt.cancel()
		}
		bm.mu.Unlock()
		return context.Canceled
	}

	maxTasks := max(effectiveSlots, sess.MaxConcurrent)
	if activeTasks >= maxTasks {
		return nil
	}

	for _, ch := range pickChallengeQueue(unsolved, bm.s.m) {
		if activeTasks >= maxTasks {
			break
		}
		if challengeHasContainer(sess.Provider, ch) && activeContainers >= effectiveSlots {
			continue
		}
		launched, needsContainer, err := bm.startChallengeSlot(ctx, rt, sess, ch, effectiveSlots, activeContainers)
		if err != nil {
			if errors.Is(err, errBenchmarkQuotaDeferred) {
				continue
			}
			var se *benchmark.StructuredError
			if errors.As(err, &se) {
				if se.RetryAfterMs > 0 {
					rt.cooldownUntil = time.Now().Add(time.Duration(se.RetryAfterMs) * time.Millisecond)
				}
				if se.Code == "ENDED" || se.Code == "EXPIRED" {
					return err
				}
				if strings.EqualFold(se.Code, "agent_environment_limit") ||
					strings.Contains(strings.ToLower(se.Message), "max active challenge instances") {
					// Platform container quota is currently full: do NOT stamp all queued
					// container challenges red or spend auto_retry_count; learn reported cap,
					// block further container launches this tick, and reclaim leaked envs.
					if capN := parseEnvCapFromMessage(se.Message); capN > 0 {
						rt.platformEnvCap = capN
						if capN < effectiveSlots {
							effectiveSlots = capN
						}
					}
					activeContainers = effectiveSlots
					reclaimed := bm.reclaimOrphanedEnvironments(ctx, rt, sess, challenges)
					if reclaimed == 0 && time.Since(rt.lastEnvWaitLogAt) >= 60*time.Second {
						rt.lastEnvWaitLogAt = time.Now()
						_ = bm.s.m.pg.AppendBenchmarkEvent(ctx, sessionID, ch.UniqueCode, "env_limit_wait",
							fmt.Sprintf("平台并发容器配额已满（上限 %d），等待空位或回收残留容器后再调度需要靶机的题目", effectiveSlots), nil)
					}
					continue
				}
			}
			if cooldown, reason := isTransientPlatformUnavailableError(err); cooldown > 0 {
				if cooldown > time.Until(rt.cooldownUntil) {
					rt.cooldownUntil = time.Now().Add(cooldown)
				}
				_ = bm.s.m.pg.AppendBenchmarkEvent(ctx, sessionID, ch.UniqueCode, "platform_cooldown",
					fmt.Sprintf("%s（冷却 %ds）：%v", reason, int(cooldown.Seconds()), err), nil)
				break
			}
			bm.scheduleChallengeAutoRetry(ctx, sessionID, ch, err.Error())
			_ = bm.s.m.pg.AppendBenchmarkEvent(ctx, sessionID, ch.UniqueCode, "slot_error", err.Error(), nil)
			continue
		}
		if launched {
			activeTasks++
			if needsContainer {
				activeContainers++
			}
		}
	}
	return nil
}

// reclaimOrphanedEnvironments probes candidate challenges on the platform when
// remote environment quota appears full, closing leaked containers whose P3Y task
// is absent or terminal and adopting legitimately running containers into DB state.
func (bm *BenchmarkManager) reclaimOrphanedEnvironments(ctx context.Context, rt *benchSessionRuntime, sess *db.BenchmarkSession, challenges []*db.BenchmarkChallenge) int {
	bm.mu.Lock()
	if time.Since(rt.lastReclaimAt) < 20*time.Second {
		bm.mu.Unlock()
		return 0
	}
	rt.lastReclaimAt = time.Now()
	bm.mu.Unlock()

	candidates := make([]*db.BenchmarkChallenge, 0, 16)
	fallback := make([]*db.BenchmarkChallenge, 0, 24)
	for _, ch := range challenges {
		if ch.ContainerStatus == "available" || ch.ContainerStatus == "pending" || ch.AttemptCount > 0 || ch.BoundTaskID != nil {
			candidates = append(candidates, ch)
		} else if challengeHasContainer(sess.Provider, ch) && len(fallback) < 20 {
			fallback = append(fallback, ch)
		}
	}
	candidates = append(candidates, fallback...)

	reclaimed := 0
	for _, ch := range candidates {
		if ctx.Err() != nil {
			break
		}
		env, err := rt.prov.GetEnvironment(ctx, ch.UniqueCode)
		if err != nil || env == nil {
			continue
		}
		if env.Status != "available" && env.Status != "pending" && len(env.Addrs) == 0 {
			continue
		}
		var boundRunning bool
		if ch.BoundTaskID != nil {
			if t, ok := bm.s.m.Task(strconv.FormatInt(*ch.BoundTaskID, 10)); ok && !isTerminalStatus(t.lifecycleSnapshot().Status) {
				boundRunning = true
			}
		}
		if boundRunning {
			_ = bm.s.m.pg.UpdateBenchmarkChallengeEnv(ctx, sess.ID, ch.UniqueCode, env.Status, env.Addrs, env.ExpiresAt, "")
			continue
		}
		if cerr := rt.prov.CloseEnvironment(ctx, ch.UniqueCode); cerr == nil {
			reclaimed++
			_ = bm.s.m.pg.UpdateBenchmarkChallengeEnv(ctx, sess.ID, ch.UniqueCode, "stopped", nil, nil, "")
			_ = bm.s.m.pg.AppendBenchmarkEvent(ctx, sess.ID, ch.UniqueCode, "env_reclaimed",
				fmt.Sprintf("已自动回收平台残留靶机容器（%s）释放并发配额", ch.Title), nil)
		}
	}
	if reclaimed > 0 {
		_ = bm.s.m.pg.ClearBenchmarkQuotaErrors(ctx, sess.ID)
	}
	return reclaimed
}

func (bm *BenchmarkManager) refreshActiveEnv(ctx context.Context, rt *benchSessionRuntime, sess *db.BenchmarkSession, ch *db.BenchmarkChallenge) {
	bm.mu.Lock()
	last := rt.lastEnvPoll[ch.UniqueCode]
	if time.Since(last) < 15*time.Second {
		bm.mu.Unlock()
		return
	}
	rt.lastEnvPoll[ch.UniqueCode] = time.Now()
	bm.mu.Unlock()

	env, err := rt.prov.GetEnvironment(ctx, ch.UniqueCode)
	if err != nil || env == nil {
		return
	}
	var exp *time.Time
	if env.ExpiresAt != nil {
		exp = env.ExpiresAt
	} else if env.RemainingSeconds > 0 {
		t := time.Now().Add(time.Duration(env.RemainingSeconds) * time.Second)
		exp = &t
	}
	_ = bm.s.m.pg.UpdateBenchmarkChallengeEnv(ctx, sess.ID, ch.UniqueCode, env.Status, env.Addrs, exp, "")

	if env.Status == "available" && env.RemainingSeconds > 0 && env.RemainingSeconds < 300 {
		if ext, eerr := rt.prov.ExtendEnvironment(ctx, ch.UniqueCode); eerr == nil && ext != nil {
			_ = bm.s.m.pg.AppendBenchmarkEvent(ctx, sess.ID, ch.UniqueCode, "env_extended",
				fmt.Sprintf("靶机容器 %s 剩余不足 5 分钟，已自动续期", ch.UniqueCode), ext)
		}
	}
}

func (bm *BenchmarkManager) checkChallengeTimeoutAndHint(ctx context.Context, rt *benchSessionRuntime, sess *db.BenchmarkSession, ch *db.BenchmarkChallenge, hasWaiting bool) bool {
	if ch.BoundTaskID == nil {
		return false
	}
	bm.mu.Lock()
	started := rt.taskStartAt[ch.UniqueCode]
	if started.IsZero() {
		if t, ok := bm.s.m.Task(strconv.FormatInt(*ch.BoundTaskID, 10)); ok {
			snap := t.lifecycleSnapshot()
			if snap.FirstRunAt > 0 {
				started = time.Unix(snap.FirstRunAt, 0)
			} else if t.CreatedAt > 0 {
				started = time.Unix(t.CreatedAt, 0)
			}
		}
		if started.IsZero() {
			started = ch.UpdatedAt
		}
		rt.taskStartAt[ch.UniqueCode] = started
	}
	bm.mu.Unlock()

	elapsed := time.Since(started)
	timeout, isFirstPass := effectiveChallengeTimeout(sess, ch)
	if sess.HintPolicy == "stagnant_only" && !isFirstPass && !ch.HintUsed && timeout > 0 {
		// For multi-flag challenges that have already solved at least one stage flag,
		// measure Hint stagnation from the latest accepted flag instead of task start,
		// so actively progressing multi-stage solves do not suffer premature -10% hint penalties.
		hintElapsed := elapsed
		if ch.FlagCount > 1 && ch.CorrectFlagCount > 0 {
			bm.mu.Lock()
			if rt.lastFlagAt == nil {
				rt.lastFlagAt = map[string]time.Time{}
			}
			lastSolved := rt.lastFlagAt[ch.UniqueCode]
			bm.mu.Unlock()
			if lastSolved.IsZero() {
				if dbTS, qerr := bm.s.m.pg.LastAcceptedBenchmarkSubmissionAt(ctx, sess.ID, ch.UniqueCode); qerr == nil && !dbTS.IsZero() {
					lastSolved = dbTS
					bm.mu.Lock()
					rt.lastFlagAt[ch.UniqueCode] = dbTS
					bm.mu.Unlock()
				}
			}
			if !lastSolved.IsZero() && lastSolved.After(started) {
				hintElapsed = time.Since(lastSolved)
			}
		}
		earlyWindow := min(20*time.Minute, timeout/2)
		shouldFetch := hintElapsed >= timeout/2 || (earlyWindow > 0 && hintElapsed >= earlyWindow && bm.isChallengeStagnant(ctx, *ch.BoundTaskID))
		if shouldFetch {
			bm.mu.Lock()
			if rt.lastHintAttempt == nil {
				rt.lastHintAttempt = map[string]time.Time{}
			}
			recentlyTried := !rt.lastHintAttempt[ch.UniqueCode].IsZero() && time.Since(rt.lastHintAttempt[ch.UniqueCode]) < 5*time.Minute
			if !recentlyTried {
				rt.lastHintAttempt[ch.UniqueCode] = time.Now()
			}
			bm.mu.Unlock()
			if !recentlyTried {
				hint, err := rt.prov.GetHint(ctx, ch.UniqueCode)
				cleanHint := strings.TrimSpace(hint)
				if err == nil {
					// Always persist hint_used=true (even when hint is empty/null) so the
					// scheduler tick never hammers /hint repeatedly for challenges without hints.
					_ = bm.s.m.pg.SaveBenchmarkChallengeHint(ctx, sess.ID, ch.UniqueCode, cleanHint)
					ch.HintUsed = true
					ch.HintContent = cleanHint
					if cleanHint != "" {
						_ = bm.s.m.pg.AppendBenchmarkEvent(ctx, sess.ID, ch.UniqueCode, "hint_fetched", "停滞自动获取题目 Hint", map[string]any{"hint": cleanHint, "elapsed_sec": int(elapsed.Seconds()), "hint_elapsed_sec": int(hintElapsed.Seconds())})
						if t, ok := bm.s.m.Task(strconv.FormatInt(*ch.BoundTaskID, 10)); ok {
							_, _ = t.Store.AddNode("fact", map[string]any{
								"summary": "【平台 Hint 提示】" + cleanHint,
								"subtype": "benchmark_hint",
							}, 0, "confirmed", "benchmark", nil)
							t.Notify()
						}
					} else {
						_ = bm.s.m.pg.AppendBenchmarkEvent(ctx, sess.ID, ch.UniqueCode, "hint_empty", "题目未配置可用 Hint，已标记不再重复请求", map[string]any{"elapsed_sec": int(elapsed.Seconds())})
					}
				} else {
					transientWait, _ := isTransientPlatformUnavailableError(err)
					var se *benchmark.StructuredError
					isClientErr := errors.As(err, &se) && se.HTTPStatus >= 400 && se.HTTPStatus < 500 && se.HTTPStatus != http.StatusTooManyRequests
					if transientWait == 0 && (isClientErr || strings.Contains(err.Error(), "不支持单独 hint 接口")) {
						_ = bm.s.m.pg.SaveBenchmarkChallengeHint(ctx, sess.ID, ch.UniqueCode, "")
						ch.HintUsed = true
						_ = bm.s.m.pg.AppendBenchmarkEvent(ctx, sess.ID, ch.UniqueCode, "hint_unavailable", "平台返回无可用 Hint，已停止重试："+err.Error(), nil)
					}
				}
			}
		}
	}
	bm.mu.Lock()
	graceAlreadyGranted := rt.momentumGraceGranted != nil && rt.momentumGraceGranted[ch.UniqueCode]
	bm.mu.Unlock()
	effectiveTimeout := timeout
	if graceAlreadyGranted && effectiveTimeout > 0 {
		effectiveTimeout += benchmarkMomentumGraceDuration
	}
	if effectiveTimeout > 0 && elapsed > effectiveTimeout && hasWaiting {
		if !graceAlreadyGranted && (ch.CorrectFlagCount > 0 || bm.hasRecentChallengeMomentum(ctx, *ch.BoundTaskID, benchmarkMomentumRecentWindow)) {
			bm.mu.Lock()
			if rt.momentumGraceGranted == nil {
				rt.momentumGraceGranted = map[string]bool{}
			}
			rt.momentumGraceGranted[ch.UniqueCode] = true
			bm.mu.Unlock()
			_ = bm.s.m.pg.AppendBenchmarkEvent(ctx, sess.ID, ch.UniqueCode, "challenge_momentum_grace",
				fmt.Sprintf("题目 %s 临近超时但检测到活跃破题动量（近 3 分钟产出新事实或已获部分 Flag），自动宽限 +%ds 避免临门一脚错杀", ch.UniqueCode, int(benchmarkMomentumGraceDuration.Seconds())),
				map[string]any{"elapsed_sec": int(elapsed.Seconds()), "grace_sec": int(benchmarkMomentumGraceDuration.Seconds()), "correct_flags": ch.CorrectFlagCount})
			return false
		}
		taskID := strconv.FormatInt(*ch.BoundTaskID, 10)
		stopReason := "单题预算超时，让出并发槽位"
		evtMsg := fmt.Sprintf("题目 %s 超过单题时间预算（%ds），已释放槽位调度后续题目", ch.UniqueCode, int(effectiveTimeout.Seconds()))
		retryReason := fmt.Sprintf("单题预算超时（%ds）", int(effectiveTimeout.Seconds()))
		if isFirstPass {
			stopReason = "首轮快筛预算到期，让出槽位优先筛查其余新题"
			evtMsg = fmt.Sprintf("题目 %s 首轮预算到期（%ds），已保留探索记忆并释放槽位，后续将使用完整预算（%ds）深度攻坚", ch.UniqueCode, int(effectiveTimeout.Seconds()), sess.PerChallengeTimeout)
			retryReason = fmt.Sprintf("首轮预算到期（%ds，转二轮完整预算 %ds）", int(effectiveTimeout.Seconds()), sess.PerChallengeTimeout)
		}
		bm.stopBoundTask(taskID, "timeout", errors.New(stopReason))
		if ch.ContainerStatus == "available" || ch.ContainerStatus == "pending" {
			_ = rt.prov.CloseEnvironment(ctx, ch.UniqueCode)
			_ = bm.s.m.pg.UpdateBenchmarkChallengeEnv(ctx, sess.ID, ch.UniqueCode, "stopped", nil, nil, "")
		}
		_ = bm.s.m.pg.AppendBenchmarkEvent(ctx, sess.ID, ch.UniqueCode, "challenge_timeout_rotate", evtMsg, nil)
		bm.scheduleChallengeAutoRetry(ctx, sess.ID, ch, retryReason)
		return true
	}
	return false
}

func parseEnvCapFromMessage(msg string) int {
	i := strings.Index(msg, "(")
	if i < 0 {
		return 0
	}
	j := strings.Index(msg[i+1:], ")")
	if j <= 0 {
		return 0
	}
	n, err := strconv.Atoi(strings.TrimSpace(msg[i+1 : i+1+j]))
	if err != nil || n <= 0 {
		return 0
	}
	return n
}

func challengeHasContainer(provider string, ch *db.BenchmarkChallenge) bool {
	if ch.SubmissionType == "choice" {
		return false
	}
	var meta struct {
		HasContainer bool `json:"has_container"`
	}
	if len(ch.Meta) > 0 && json.Unmarshal(ch.Meta, &meta) == nil {
		if meta.HasContainer {
			return true
		}
	}
	return strings.EqualFold(provider, "tsecbench") && len(ch.ContainerAddr) > 0
}

func isNoFlagBenchmarkChallenge(ch *db.BenchmarkChallenge) bool {
	if ch == nil {
		return false
	}
	title := strings.ToLower(ch.Title)
	desc := strings.ToLower(ch.Description)
	return strings.Contains(title, "[无flag]") || strings.Contains(desc, "本题无flag")
}

func isTransientPlatformUnavailableError(err error) (time.Duration, string) {
	if err == nil {
		return 0, ""
	}
	var se *benchmark.StructuredError
	if errors.As(err, &se) {
		code := strings.ToLower(strings.TrimSpace(se.Code))
		if code == "maintenance_mode" || strings.Contains(strings.ToLower(se.Message), "maintenance") {
			wait := 30 * time.Second
			if se.RetryAfterMs > 0 {
				wait = max(wait, time.Duration(se.RetryAfterMs)*time.Millisecond)
			}
			return wait, "平台处于系统维护状态"
		}
		if se.HTTPStatus == 429 || strings.Contains(code, "rate_limit") {
			wait := 15 * time.Second
			if se.RetryAfterMs > 0 {
				wait = max(wait, time.Duration(se.RetryAfterMs)*time.Millisecond)
			}
			return wait, "触发平台限流配额"
		}
		if se.HTTPStatus >= 500 || se.Retryable {
			return 20 * time.Second, "平台服务暂时不可用"
		}
	}
	lower := strings.ToLower(err.Error())
	for _, needle := range []string{
		"server misbehaving",
		"dial tcp",
		"connection reset",
		"connection refused",
		"stream error",
		"eof",
		"tls:",
		"context deadline exceeded",
		"i/o timeout",
	} {
		if strings.Contains(lower, needle) {
			return 15 * time.Second, "平台网络或连接瞬时异常"
		}
	}
	return 0, ""
}

func (bm *BenchmarkManager) isChallengeStagnant(ctx context.Context, taskID int64) bool {
	if bm == nil || bm.s == nil || bm.s.m == nil || taskID <= 0 {
		return false
	}
	t, ok := bm.s.m.Task(strconv.FormatInt(taskID, 10))
	if !ok || t == nil || t.Store == nil {
		return false
	}
	if _, total, err := t.Store.NodesPage(db.NodeFilter{Kinds: []string{"intent"}, States: []string{"exhausted"}}, 1, 1); err == nil && total > 0 {
		return true
	}
	if bm.s.m.pg != nil && t.ExpID > 0 {
		var hasCritic bool
		if err := bm.s.m.pg.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM activity WHERE exploration_id=$1 AND kind='critic')`, t.ExpID).Scan(&hasCritic); err == nil && hasCritic {
			return true
		}
	}
	return false
}

// hasRecentChallengeMomentum reports whether taskID recorded a new confirmed
// (non-origin) Fact within window, indicating active solving momentum.
func (bm *BenchmarkManager) hasRecentChallengeMomentum(ctx context.Context, taskID int64, window time.Duration) bool {
	if bm == nil || bm.s == nil || bm.s.m == nil || bm.s.m.pg == nil || taskID <= 0 || window <= 0 {
		return false
	}
	t, ok := bm.s.m.Task(strconv.FormatInt(taskID, 10))
	if !ok || t == nil || t.ExpID <= 0 {
		return false
	}
	var hasRecent bool
	cutoff := time.Now().Add(-window)
	if err := bm.s.m.pg.QueryRowContext(ctx, `SELECT EXISTS(
		SELECT 1 FROM exploration_nodes
		WHERE exploration_id=$1 AND kind='fact' AND state='confirmed' AND created_at >= $2
	)`, t.ExpID, cutoff).Scan(&hasRecent); err == nil && hasRecent {
		return true
	}
	return false
}

func challengeFactCount(m *Manager, boundTaskID *int64) int {
	if m == nil || boundTaskID == nil || *boundTaskID <= 0 {
		return 0
	}
	t, ok := m.Task(strconv.FormatInt(*boundTaskID, 10))
	if !ok || t == nil || t.Store == nil {
		return 0
	}
	_, total, err := t.Store.NodesPage(db.NodeFilter{Kinds: []string{"fact"}}, 1, 1)
	if err != nil {
		return 0
	}
	return total
}

type difficultyTier struct {
	rank     int
	keywords []string
}

var benchmarkDifficultyTiers = []difficultyTier{
	// Match composite modifiers before single base difficulty words.
	{rank: 150, keywords: []string{"very easy", "veryeasy", "super easy", "极简"}},
	{rank: 250, keywords: []string{"easy-medium", "medium-easy", "easy medium", "medium easy", "较易"}},
	{rank: 350, keywords: []string{"medium-hard", "hard-medium", "medium hard", "hard medium"}},
	{rank: 500, keywords: []string{"very hard", "veryhard", "insane", "expert", "extreme", "hell", "master", "nightmare", "brutal", "lunatic", "地狱", "极难", "专家", "魔鬼", "超难"}},
	{rank: 100, keywords: []string{"checkin", "check-in", "welcome", "baby", "trivial", "warmup", "warm-up", "warm up", "intro", "introductory", "beginner", "newbie", "rookie", "piece of cake", "签到", "热身", "入门", "新手"}},
	{rank: 200, keywords: []string{"easy", "simple", "basic", "elementary", "junior", "low", "简单", "容易", "初级", "低"}},
	{rank: 300, keywords: []string{"medium", "normal", "moderate", "intermediate", "standard", "average", "regular", "mid", "med", "中等", "中级", "普通", "中"}},
	{rank: 400, keywords: []string{"hard", "difficult", "challenging", "advanced", "tough", "senior", "high", "困难", "较难", "高级", "高"}},
}

func challengeDifficultyRank(ch *db.BenchmarkChallenge) (bool, int) {
	if ch == nil {
		return false, 0
	}
	raw := strings.ToLower(strings.TrimSpace(ch.Difficulty))
	switch raw {
	case "", "auto", "unknown", "none", "null", "n/a", "na", "-", "--", "unset", "未标记", "未知", "自动":
		if ch.Level > 0 {
			return true, ch.Level * 100
		}
		return false, 0
	}

	spaced := strings.NewReplacer("-", " ", "_", " ", ":", " ", "/", " ").Replace(raw)
	tokens := strings.FieldsFunc(raw, func(r rune) bool {
		switch r {
		case ' ', '\t', '-', '_', '/', ':', '|', '(', ')', '[', ']', ',', '，', '：':
			return true
		}
		return false
	})
	matchKeyword := func(kw string) bool {
		if raw == kw || spaced == kw {
			return true
		}
		for _, tok := range tokens {
			if tok == kw {
				return true
			}
		}
		// Multi-character CJK labels frequently appear inside compound tags (e.g. "困难(Web)").
		return len([]rune(kw)) >= 2 && kw[0] >= 0x80 && strings.Contains(raw, kw)
	}
	for _, tier := range benchmarkDifficultyTiers {
		for _, kw := range tier.keywords {
			if matchKeyword(kw) {
				return true, tier.rank
			}
		}
	}

	if stars := strings.Count(raw, "★") + strings.Count(raw, "⭐"); stars > 0 {
		return true, stars * 100
	}

	// Accept numeric or prefixed levels ("1", "2", "lv2", "lv.3", "level 4", "2星").
	numStr := strings.TrimSpace(spaced)
	for _, prefix := range []string{"level ", "level", "tier ", "tier", "lv.", "lv ", "lv", "l", "d"} {
		if strings.HasPrefix(numStr, prefix) {
			numStr = strings.TrimSpace(strings.TrimPrefix(numStr, prefix))
			break
		}
	}
	numStr = strings.TrimRight(numStr, "星级")
	if n, err := strconv.Atoi(strings.TrimSpace(numStr)); err == nil && n > 0 {
		return true, n * 100
	}

	if ch.Level > 0 {
		return true, ch.Level * 100
	}
	return false, 0
}

func pickChallengeQueue(unsolved []*db.BenchmarkChallenge, m *Manager) []*db.BenchmarkChallenge {
	now := time.Now()
	idle := make([]*db.BenchmarkChallenge, 0, len(unsolved))
	highValueHarvest := make(map[string]bool, len(unsolved))
	hasAnyDifficulty := false
	maxRetries := benchmarkMaxAutoRetries()
	for _, ch := range unsolved {
		if isNoFlagBenchmarkChallenge(ch) {
			continue
		}
		if ch.BoundTaskID != nil && m != nil {
			if t, ok := m.Task(strconv.FormatInt(*ch.BoundTaskID, 10)); ok && !isTerminalStatus(t.lifecycleSnapshot().Status) {
				continue
			}
		}
		if ch.NextRetryAt != nil && now.Before(*ch.NextRetryAt) {
			continue
		}
		if isBenchmarkRetryExhausted(ch, maxRetries) {
			continue
		}
		if ch.AttemptCount == 1 && ch.AutoRetryCount <= 1 && ch.TotalScore >= 700 && challengeFactCount(m, ch.BoundTaskID) >= 4 {
			highValueHarvest[ch.UniqueCode] = true
		}
		if ok, _ := challengeDifficultyRank(ch); ok {
			hasAnyDifficulty = true
		}
		idle = append(idle, ch)
	}
	firstPassActive := benchmarkFirstPassTimeoutSec() > 0
	bucket := func(ch *db.BenchmarkChallenge) int {
		if firstPassActive {
			// Two-phase MLFQ: finish fast first-pass screening on all untried challenges (AttemptCount == 0)
			// before promoting retried high-value challenges into full-budget Round 2+.
			if ch.AttemptCount == 0 {
				return 0
			}
			if highValueHarvest[ch.UniqueCode] {
				return 1
			}
			return 2
		}
		if highValueHarvest[ch.UniqueCode] {
			return 0
		}
		if ch.AttemptCount == 0 {
			return 1
		}
		return 2
	}
	const unknownDifficultyRank = 350
	sort.SliceStable(idle, func(i, j int) bool {
		bi, bj := bucket(idle[i]), bucket(idle[j])
		if bi != bj {
			return bi < bj
		}
		if highValueHarvest[idle[i].UniqueCode] && highValueHarvest[idle[j].UniqueCode] {
			if idle[i].TotalScore != idle[j].TotalScore {
				return idle[i].TotalScore > idle[j].TotalScore
			}
			return idle[i].ID < idle[j].ID
		}
		if idle[i].AttemptCount != idle[j].AttemptCount {
			return idle[i].AttemptCount < idle[j].AttemptCount
		}
		if idle[i].AutoRetryCount != idle[j].AutoRetryCount {
			return idle[i].AutoRetryCount < idle[j].AutoRetryCount
		}
		if hasAnyDifficulty {
			hasI, rankI := challengeDifficultyRank(idle[i])
			hasJ, rankJ := challengeDifficultyRank(idle[j])
			if !hasI {
				rankI = unknownDifficultyRank
			}
			if !hasJ {
				rankJ = unknownDifficultyRank
			}
			if rankI != rankJ {
				return rankI < rankJ
			}
			if hasI && hasJ && idle[i].Level != idle[j].Level && (idle[i].Level > 0 || idle[j].Level > 0) {
				if idle[i].Level > 0 && idle[j].Level > 0 {
					return idle[i].Level < idle[j].Level
				}
				return idle[i].Level > 0
			}
		}
		if bi == 2 && idle[i].TotalScore != idle[j].TotalScore {
			return idle[i].TotalScore > idle[j].TotalScore
		}
		return idle[i].ID < idle[j].ID
	})
	return idle
}

var errBenchmarkQuotaDeferred = errors.New("container slot quota full")

func (bm *BenchmarkManager) startChallengeSlot(ctx context.Context, rt *benchSessionRuntime, sess *db.BenchmarkSession, ch *db.BenchmarkChallenge, effectiveSlots, activeContainers int) (launched bool, needsContainer bool, err error) {
	// 1. Always fetch fresh challenge detail first so description, category,
	//    has_container, and attachments are accurate before reserving container slots.
	detail, derr := rt.prov.GetChallengeDetail(ctx, ch.UniqueCode)
	if derr != nil {
		return false, false, fmt.Errorf("拉取题目详情失败: %w", derr)
	}
	if detail != nil {
		_ = bm.s.m.pg.SyncBenchmarkChallenges(ctx, sess.ID, []db.BenchmarkChallengeUpsert{{
			UniqueCode:       ch.UniqueCode,
			Title:            detail.Title,
			Description:      detail.Description,
			Category:         detail.Category,
			Difficulty:       detail.Difficulty,
			Level:            detail.Level,
			SubmissionType:   detail.SubmissionType,
			TotalScore:       detail.TotalScore,
			CumulativeScore:  detail.CumulativeScore,
			FlagCount:        detail.FlagCount,
			CorrectFlagCount: detail.CorrectFlagCount,
			IsCompleted:      detail.IsCompleted,
			ContainerStatus:  ch.ContainerStatus,
			ContainerAddr:    ch.ContainerAddr,
			Meta:             benchmark.ChallengeMetaJSON(*detail),
		}})
		if reloaded, rerr := bm.s.m.pg.GetBenchmarkChallenge(ctx, sess.ID, ch.UniqueCode); rerr == nil && reloaded != nil {
			ch = reloaded
		}
		if ch.LastError != "" {
			_ = bm.s.m.pg.UpdateBenchmarkChallengeEnv(ctx, sess.ID, ch.UniqueCode, ch.ContainerStatus, ch.ContainerAddr, ch.EnvExpiresAt, "")
			ch.LastError = ""
		}
		if isNoFlagBenchmarkChallenge(ch) {
			_ = bm.s.m.pg.AppendBenchmarkEvent(ctx, sess.ID, ch.UniqueCode, "challenge_skipped_no_flag",
				fmt.Sprintf("题目 %s 声明无 Flag，自动跳过调度", ch.Title), nil)
			return false, false, nil
		}
		if detail.IsCompleted {
			_ = bm.s.m.pg.AppendBenchmarkEvent(ctx, sess.ID, ch.UniqueCode, "challenge_already_solved",
				fmt.Sprintf("题目 %s 在平台端已处于完成状态，自动跳过启动", ch.Title), nil)
			return false, false, nil
		}
	}

	needsContainer = (detail != nil && detail.HasContainer) || challengeHasContainer(sess.Provider, ch)
	if needsContainer && activeContainers >= effectiveSlots {
		return false, true, errBenchmarkQuotaDeferred
	}

	var env *benchmark.EnvState
	if needsContainer {
		st, serr := rt.prov.StartEnvironment(ctx, ch.UniqueCode)
		if serr != nil {
			return false, true, serr
		}
		env = st
		// Persist initial env state immediately (e.g. pending) so UI updates live during startup poll.
		if env != nil {
			_ = bm.s.m.pg.UpdateBenchmarkChallengeEnv(ctx, sess.ID, ch.UniqueCode, env.Status, env.Addrs, env.ExpiresAt, "")
			ch.ContainerStatus = env.Status
			ch.ContainerAddr = env.Addrs
			ch.EnvExpiresAt = env.ExpiresAt
		}
		// Poll until environment becomes available with endpoints (repeating
		// idempotent start periodically when platform keeps returning pending).
		lastStartAt := time.Now()
		for deadline := time.Now().Add(45 * time.Second); env != nil && env.Status == "pending" && time.Now().Before(deadline); {
			select {
			case <-ctx.Done():
				return false, true, ctx.Err()
			case <-time.After(2 * time.Second):
			}
			if next, gerr := rt.prov.GetEnvironment(ctx, ch.UniqueCode); gerr == nil && next != nil {
				env = next
			} else if time.Since(lastStartAt) >= 10*time.Second {
				if retrySt, rerr := rt.prov.StartEnvironment(ctx, ch.UniqueCode); rerr == nil && retrySt != nil {
					env = retrySt
				}
				lastStartAt = time.Now()
			}
		}
		var exp *time.Time
		if env != nil {
			if env.ExpiresAt != nil {
				exp = env.ExpiresAt
			} else if env.RemainingSeconds > 0 {
				t := time.Now().Add(time.Duration(env.RemainingSeconds) * time.Second)
				exp = &t
			}
			_ = bm.s.m.pg.UpdateBenchmarkChallengeEnv(ctx, sess.ID, ch.UniqueCode, env.Status, env.Addrs, exp, "")
			ch.ContainerStatus = env.Status
			ch.ContainerAddr = env.Addrs
			ch.EnvExpiresAt = exp
		}
		if env == nil || len(env.Addrs) == 0 || env.Status == "failed" || env.Status == "stopped" {
			_ = rt.prov.CloseEnvironment(ctx, ch.UniqueCode)
			ch.ContainerStatus = "stopped"
			ch.ContainerAddr = nil
			return false, true, fmt.Errorf("靶机容器未就绪或未返回访问地址（status=%v）", func() string {
				if env == nil {
					return "nil"
				}
				return env.Status
			}())
		}
	}

	// Collect attachments metadata before creating goal so Planner/Worker know mounted filenames.
	var meta struct {
		Files []benchmark.AttachmentSpec `json:"files"`
	}
	if len(ch.Meta) > 0 {
		_ = json.Unmarshal(ch.Meta, &meta)
	}
	if detail != nil && len(detail.Files) > 0 {
		meta.Files = detail.Files
	}
	attachNames := make([]string, 0, len(meta.Files))
	for _, f := range meta.Files {
		if strings.TrimSpace(f.Name) != "" {
			attachNames = append(attachNames, strings.TrimSpace(f.Name))
		}
	}

	chalType := benchmark.InferChallengeType(ch.UniqueCode, ch.Category, ch.Description)
	if chalType == "auto" {
		chalType = "web"
	}
	vpnCfg, vpnHash, vpnFilename, _ := prepareTaskVPNForCreate("ctf", rt.cfg.CTFVPNConfig, rt.cfg.CTFVPNFilename)

	sid := sess.ID
	prevTaskIDs, _ := bm.s.m.pg.ResolveChallengeSourceTaskIDs(ctx, sess.ID, ch.UniqueCode, ch.HistoryTaskIDs, ch.BoundTaskID)
	goal := buildBenchmarkChallengeGoal(ch, env, attachNames, prevTaskIDs)
	desc := fmt.Sprintf("[测评#%d %s] %s", sess.ID, ch.UniqueCode, ch.Title)

	t, err := bm.s.m.CreateTaskWithOptions(desc, goal, db.TaskCreateOptions{
		Name:                 fmt.Sprintf("[%s] %s", ch.UniqueCode, ch.Title),
		Mode:                 "ctf",
		ChallengeType:        chalType,
		CTFVerifyMode:        db.CTFVerifyFlag,
		CTFVPNConfig:         vpnCfg,
		CTFVPNHash:           vpnHash,
		CTFVPNFilename:       vpnFilename,
		LLMProfileIDs:        sess.LLMProfileIDs,
		SourceTaskIDs:        prevTaskIDs,
		TimeoutSeconds:       sess.PerChallengeTimeout,
		PlanHeartbeatSeconds: 30,
		ZeroTouch:            true,
		BenchmarkSessionID:   &sid,
	})
	if err != nil {
		if needsContainer {
			_ = rt.prov.CloseEnvironment(ctx, ch.UniqueCode)
			_ = bm.s.m.pg.UpdateBenchmarkChallengeEnv(ctx, sess.ID, ch.UniqueCode, "stopped", nil, nil, err.Error())
		}
		return false, needsContainer, err
	}
	numericID, _ := strconv.ParseInt(t.ID, 10, 64)

	store := artifacts.Store{Root: bm.s.m.dir}
	for _, f := range meta.Files {
		fid := f.ID
		if fid == "" {
			fid = f.URL
		}
		if fid == "" {
			fid = f.Name
		}
		fname, raw, derr := rt.prov.DownloadAttachment(ctx, ch.UniqueCode, fid)
		if derr != nil || len(raw) == 0 {
			_ = bm.s.m.pg.AppendBenchmarkEvent(ctx, sess.ID, ch.UniqueCode, "attachment_warn",
				fmt.Sprintf("附件 %s 下载失败：%v", f.Name, derr), nil)
			continue
		}
		if fname == "" {
			fname = f.Name
		}
		if _, aerr := store.Add("task", t.ID, fname, "attachment", bytes.NewReader(raw)); aerr != nil {
			_ = bm.s.m.pg.AppendBenchmarkEvent(ctx, sess.ID, ch.UniqueCode, "attachment_warn",
				fmt.Sprintf("附件 %s 写入失败：%v", fname, aerr), nil)
		}
	}

	if err := bm.s.m.pg.BindBenchmarkChallengeTask(ctx, sess.ID, ch.UniqueCode, numericID); err != nil {
		return false, needsContainer, err
	}
	bm.mu.Lock()
	rt.taskStartAt[ch.UniqueCode] = time.Now()
	if rt.momentumGraceGranted != nil {
		delete(rt.momentumGraceGranted, ch.UniqueCode)
	}
	bm.mu.Unlock()

	bm.s.prewarmTaskVPN(t, vpnHash, vpnCfg)
	// Direct Lead-Solver: startTaskEngine seeds a long-horizon phase="exploit" intent
	// immediately after Phase-0 Precheck so Worker launches on Turn 1 with 0 Planner LLM lag.
	bm.s.launchTask(t, goal, false)
	eventMsg := fmt.Sprintf("题目已分配槽位并启动零交互求解（子任务 #%s）", t.ID)
	if len(prevTaskIDs) > 0 {
		eventMsg = fmt.Sprintf("题目已分配槽位并启动零交互求解（子任务 #%s，继承前序任务 #%v 探索记忆）", t.ID, prevTaskIDs)
	}
	_ = bm.s.m.pg.AppendBenchmarkEvent(ctx, sess.ID, ch.UniqueCode, "challenge_started",
		eventMsg, map[string]any{
			"task_id":         t.ID,
			"addrs":           ch.ContainerAddr,
			"source_task_ids": prevTaskIDs,
		})
	return true, needsContainer, nil
}

func buildBenchmarkChallengeGoal(ch *db.BenchmarkChallenge, env *benchmark.EnvState, attachNames []string, prevTaskIDs []int64) string {
	var b strings.Builder
	fmt.Fprintf(&b, "题目代号：%s\n标题：%s\n分类：%s | 难度：%s | 提交类型：%s | Flag 数：%d\n",
		ch.UniqueCode, ch.Title, ch.Category, ch.Difficulty, ch.SubmissionType, ch.FlagCount)
	addrs := ch.ContainerAddr
	if env != nil && len(env.Addrs) > 0 {
		addrs = env.Addrs
	}
	if len(addrs) > 0 {
		fmt.Fprintf(&b, "靶机访问地址：%s\n", strings.Join(addrs, ", "))
	}
	if len(attachNames) > 0 {
		fmt.Fprintf(&b, "题目附件（已挂载至 /work/.inputs）：%s\n", strings.Join(attachNames, ", "))
	}
	if ch.Description != "" {
		fmt.Fprintf(&b, "\n【题目描述】\n%s\n", ch.Description)
	}
	if len(prevTaskIDs) > 0 {
		idStrs := make([]string, 0, len(prevTaskIDs))
		for _, pid := range prevTaskIDs {
			idStrs = append(idStrs, fmt.Sprintf("#%d", pid))
		}
		fmt.Fprintf(&b, "\n【前序探索记忆继承（来自任务 %s）】\n本题此前因超时或异常中断后重新调度，系统已自动将前序任务的探索黑板（已确认事实 fact、线索 finding、冷摘要与终态意图总结）以只读源任务形式继承到当前探索态势中。\n请先查阅前序任务的已有探索发现，严禁从头重跑已证实失败的字典穷举、无效脚本或本地高耗时暴力破解，直接围绕前序突破口或平台 Hint 推进；若本轮重新启动了靶机容器，一切网络探测与漏洞利用请以本轮最新【靶机访问地址】为准。\n", strings.Join(idStrs, ", "))
	}
	if ch.SubmissionType == "choice" {
		b.WriteString("\n请结合题目描述与附件完成分析，并通过 `benchmark_submit_choice` 提交正确选项 ID 数组。")
	} else {
		b.WriteString("\n请在隔离容器中完成题目分析与漏洞利用，拿到全部 Flag 并由系统或 `ctf_submit_flag` 提交验证。")
	}
	return b.String()
}

// ---- Runtime Hooks called by CTF Service & Agent ----

func (bm *BenchmarkManager) contextForTask(ctx context.Context, taskID int64, _ string) string {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	sess, ch, err := bm.s.m.pg.FindBenchmarkByTaskID(ctx, taskID)
	if err != nil || sess == nil || ch == nil {
		return ""
	}
	var meta struct {
		SubFlags []benchmark.SubFlagSpec `json:"sub_flags"`
		Choice   *benchmark.ChoiceMeta   `json:"choice"`
	}
	_ = json.Unmarshal(ch.Meta, &meta)
	cfg := parseSessionConfig(sess.Config)

	var b strings.Builder
	fmt.Fprintf(&b, "\n【测评题目元信息】平台=%s | 题目=%s (%s) | 进度=%d/%d Flag (%d/%d 分) | 状态=%s\n",
		sess.Provider, ch.UniqueCode, ch.Title, ch.CorrectFlagCount, ch.FlagCount, ch.CumulativeScore, ch.TotalScore, ch.ContainerStatus)
	if len(ch.ContainerAddr) > 0 {
		fmt.Fprintf(&b, "实时靶机地址：%s\n", strings.Join(ch.ContainerAddr, ", "))
	}
	if len(meta.SubFlags) > 0 {
		raw, _ := json.Marshal(meta.SubFlags)
		fmt.Fprintf(&b, "多 Flag 子项：%s\n", string(raw))
	}
	if meta.Choice != nil {
		raw, _ := json.Marshal(meta.Choice)
		fmt.Fprintf(&b, "【客观选择题选项（请调用 benchmark_submit_choice 提交）】：%s\n", string(raw))
	}
	if ch.HintContent != "" {
		fmt.Fprintf(&b, "【已获取 Hint】：%s\n", ch.HintContent)
	}
	if ch.FlagCount > 1 && ch.CorrectFlagCount < ch.FlagCount {
		fmt.Fprintf(&b, "\n【多阶段渗透接力指引（共 %d 个 Flag，当前进度 %d/%d）】\n"+
			"- 在集齐全部 %d 个 Flag（complete=true）前，拿到某阶段 Flag 后**严禁退出当前意图**，必须留在当前热会话与同一 /work 工作区继续向下阶段推进！\n"+
			"- 阶段破局顺序：1) 拿到立足点后立即将交互通道与获取的凭据/私钥（/work/creds.txt、/work/id_rsa 并 chmod 600）固化至 /work 下以便跨阶段与重跑复用；2) 排查本机敏感配置/环境变量/.env/数据库/SSH 密钥与权限边界（sudo -l、SUID、docker.sock、特权挂载、K8s token）；3) 从已进入节点内部查看双网卡/路由/邻接表/端口监听（ip a、ip route、/etc/hosts、arp -n、ss -tulpn），探测内网邻居网段（如 172.x/10.x/192.168.x，严禁触碰测评平台自身网关）。\n"+
			"- 内置跳板与代理工具（沙箱已预装 ssh / sshpass / proxychains4）：\n"+
			"  * 动态 SOCKS5 隧道：`sshpass -p '<pwd>' ssh -o StrictHostKeyChecking=no -f -N -D 127.0.0.1:1080 user@<pivot_host>`（或使用 `-i /work/id_rsa` / `-L` 本地端口转发）；\n"+
			"  * 代理链配置与调用：在 `/work/proxychains.conf` 写入 `strict_chain` 与 `[ProxyList]\\nsocks5 127.0.0.1 1080`，随后使用 `proxychains4 -q -f /work/proxychains.conf <命令或脚本>` 直接穿透访问深层内网目标。\n",
			ch.FlagCount, ch.CorrectFlagCount, ch.FlagCount, ch.FlagCount)
	}
	if strings.TrimSpace(cfg.SkillInstructions) != "" {
		fmt.Fprintf(&b, "\n【接入平台 Skill 规范 (%s)】\n%s\n", cfg.SkillName, cfg.SkillInstructions)
	}
	return b.String()
}

func (bm *BenchmarkManager) extraToolsForTask(ctx context.Context, taskID int64) []actool.CoreTool {
	sess, ch, err := bm.s.m.pg.FindBenchmarkByTaskID(ctx, taskID)
	if err != nil || sess == nil || ch == nil || sess.Provider != "generic_mcp" {
		return nil
	}
	rt, err := bm.runtimeFor(sess)
	if err != nil {
		return nil
	}
	bm.mu.Lock()
	if rt.toolsLoaded {
		out := append([]actool.CoreTool(nil), rt.extraTools...)
		bm.mu.Unlock()
		return out
	}
	bm.mu.Unlock()

	gc, ok := rt.prov.(*benchmark.GenericMCPClient)
	if !ok {
		return nil
	}
	tctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	tools, derr := gc.DiscoverSafeTools(tctx)
	cancel()
	if derr != nil {
		return nil
	}
	bm.mu.Lock()
	rt.extraTools = tools
	rt.toolsLoaded = true
	bm.mu.Unlock()
	return tools
}

func (bm *BenchmarkManager) handleFlagCandidate(ctx context.Context, taskID int64, _ string, value, subFlagID string) (string, bool, error) {
	sess, ch, err := bm.s.m.pg.FindBenchmarkByTaskID(ctx, taskID)
	if err != nil || sess == nil || ch == nil {
		return "", false, nil
	}
	return bm.submitToPlatform(ctx, sess, ch, taskID, benchmark.SubmitRequest{
		UniqueCode: ch.UniqueCode,
		Flag:       strings.TrimSpace(value),
		SubFlagID:  strings.TrimSpace(subFlagID),
	}, strings.TrimSpace(value))
}

func (bm *BenchmarkManager) handleChoice(ctx context.Context, taskID int64, choices []string) (string, bool, error) {
	sess, ch, err := bm.s.m.pg.FindBenchmarkByTaskID(ctx, taskID)
	if err != nil || sess == nil || ch == nil {
		return "", false, nil
	}
	answerText := strings.Join(choices, ",")
	return bm.submitToPlatform(ctx, sess, ch, taskID, benchmark.SubmitRequest{
		UniqueCode: ch.UniqueCode,
		Choice:     choices,
	}, answerText)
}

// handleRequestHint lets an active benchmark Lead-Solver request the platform Hint
// when genuinely stuck, protected by an 8-minute anti-laziness gate (unless already
// stagnant) and global per-challenge idempotency.
func (bm *BenchmarkManager) handleRequestHint(ctx context.Context, taskID int64, reason string) (string, bool, error) {
	sess, ch, err := bm.s.m.pg.FindBenchmarkByTaskID(ctx, taskID)
	if err != nil || sess == nil || ch == nil {
		return "", false, nil
	}
	if ch.HintUsed {
		if clean := strings.TrimSpace(ch.HintContent); clean != "" {
			return "【已缓存的平台 Hint】" + clean, true, nil
		}
		return "本题此前已向平台查询过 Hint，平台未配置可用 Hint，请换向独立突破。", true, nil
	}
	if sess.HintPolicy == "never" {
		return "当前测评会话已将 hint_policy 设为 never（禁用 Hint），请独立解题。", true, nil
	}
	rt, err := bm.runtimeFor(sess)
	if err != nil {
		return "", true, err
	}
	bm.mu.Lock()
	started := rt.taskStartAt[ch.UniqueCode]
	bm.mu.Unlock()
	if started.IsZero() {
		if t, ok := bm.s.m.Task(strconv.FormatInt(taskID, 10)); ok {
			snap := t.lifecycleSnapshot()
			if snap.FirstRunAt > 0 {
				started = time.Unix(snap.FirstRunAt, 0)
			} else if t.CreatedAt > 0 {
				started = time.Unix(t.CreatedAt, 0)
			}
		}
	}
	elapsed := time.Duration(0)
	if !started.IsZero() {
		elapsed = time.Since(started)
	}
	if elapsed < benchmarkActiveHintMinElapsed && !bm.isChallengeStagnant(ctx, taskID) {
		remSec := int((benchmarkActiveHintMinElapsed - elapsed).Seconds())
		if remSec < 1 {
			remSec = 1
		}
		return fmt.Sprintf("【Hint 门禁拦截】本题当前仅运行 %d 秒（未满 %d 分钟防偷懒门禁且未触发停滞），暂不允许拉取扣分 Hint。请先完成活体探测、附件核心逻辑排查或并行 ask_helper 审计（还需 %d 秒后可再次申请）。",
			int(elapsed.Seconds()), int(benchmarkActiveHintMinElapsed/time.Minute), remSec), true, nil
	}

	hint, herr := rt.prov.GetHint(ctx, ch.UniqueCode)
	if herr != nil {
		transientWait, _ := isTransientPlatformUnavailableError(herr)
		var se *benchmark.StructuredError
		isClientErr := errors.As(herr, &se) && se.HTTPStatus >= 400 && se.HTTPStatus < 500 && se.HTTPStatus != http.StatusTooManyRequests
		if transientWait == 0 && (isClientErr || strings.Contains(herr.Error(), "不支持单独 hint 接口")) {
			_ = bm.s.m.pg.SaveBenchmarkChallengeHint(ctx, sess.ID, ch.UniqueCode, "")
			_ = bm.s.m.pg.AppendBenchmarkEvent(ctx, sess.ID, ch.UniqueCode, "hint_unavailable", "Worker 主动申请 Hint 但平台返回无可用 Hint："+herr.Error(), map[string]any{"reason": reason})
			return "平台返回本题无可用 Hint（" + herr.Error() + "），已记录不再重复请求，请切换方向继续突破。", true, nil
		}
		return "", true, herr
	}
	cleanHint := strings.TrimSpace(hint)
	_ = bm.s.m.pg.SaveBenchmarkChallengeHint(ctx, sess.ID, ch.UniqueCode, cleanHint)
	if cleanHint == "" {
		_ = bm.s.m.pg.AppendBenchmarkEvent(ctx, sess.ID, ch.UniqueCode, "hint_empty", "Worker 主动申请 Hint，题目未配置可用 Hint", map[string]any{"reason": reason, "elapsed_sec": int(elapsed.Seconds())})
		return "本题平台未配置可用 Hint，已标记不再重复请求，请切换其他攻击面独立突破。", true, nil
	}
	_ = bm.s.m.pg.AppendBenchmarkEvent(ctx, sess.ID, ch.UniqueCode, "hint_fetched", "Worker 主动申请获取平台 Hint", map[string]any{
		"source":      "active_worker_request",
		"reason":      reason,
		"hint":        cleanHint,
		"elapsed_sec": int(elapsed.Seconds()),
	})
	if t, ok := bm.s.m.Task(strconv.FormatInt(taskID, 10)); ok {
		_, _ = t.Store.AddNode("fact", map[string]any{
			"summary": "【平台 Hint 提示】" + cleanHint,
			"detail":  cleanHint,
			"subtype": "benchmark_hint",
		}, 0, "confirmed", "benchmark", nil)
	}
	return "【平台官方 Hint】" + cleanHint + "\n（已同步写入探索图谱，请立即按此线索调整利用路线）", true, nil
}

// resolveBenchmarkCTFCandidates closes pending 'candidate' rows in ctf_candidates
// after automatic platform grading so zero-touch workers never enter an endless
// ctfSubmissionProvider waiting handoff loop.
func (bm *BenchmarkManager) resolveBenchmarkCTFCandidates(ctx context.Context, taskID int64, matchValue, state, notes string, finish bool) {
	t, ok := bm.s.m.Task(strconv.FormatInt(taskID, 10))
	if !ok || t == nil {
		return
	}
	cands, err := bm.s.m.pg.CTFCandidates(ctx, taskID)
	if err != nil {
		return
	}
	want := strings.TrimSpace(matchValue)
	for _, c := range cands {
		if c.State != "candidate" {
			continue
		}
		if want != "" && strings.TrimSpace(c.Value) != want {
			continue
		}
		if _, derr := bm.s.m.DecideCTFAnswer(ctx, t, c.ID, c.Revision, state, notes, finish); derr != nil {
			continue
		}
		// Only first Finish=true is needed; DecideCTFCandidate also batches sibling identical values.
		finish = false
	}
}

var customPrefixFlagRe = regexp.MustCompile(`^([A-Za-z0-9_\-]{2,20})\{([^\r\n{}]{1,256})\}$`)

// normalizedStandardFlagFallback rewrites a rejected custom-prefix CTF flag
// (e.g. SCTF{...}, DASCTF{...}, BCTF{...}) into the standard flag{...} format
// used by many benchmark judges. Returns ("", false) when raw already uses a
// flag{...} prefix (case-insensitive) or does not match prefix{body}.
func normalizedStandardFlagFallback(raw string) (string, bool) {
	m := customPrefixFlagRe.FindStringSubmatch(strings.TrimSpace(raw))
	if len(m) != 3 || strings.EqualFold(m[1], "flag") {
		return "", false
	}
	return "flag{" + m[2] + "}", true
}

func (bm *BenchmarkManager) submitToPlatform(ctx context.Context, sess *db.BenchmarkSession, ch *db.BenchmarkChallenge, taskID int64, req benchmark.SubmitRequest, answerDisplay string) (string, bool, error) {
	if ch.IsCompleted {
		bm.resolveBenchmarkCTFCandidates(ctx, taskID, answerDisplay, "accepted", "该题已完成", false)
		return `{"correct":true,"already_completed":true,"message":"该题已完成"}`, true, nil
	}
	submitted, wasCorrect, _ := bm.s.m.pg.LookupSubmittedBenchmarkAnswer(ctx, sess.ID, ch.UniqueCode, req.SubFlagID, answerDisplay)
	if !submitted {
		if fbFlag, ok := normalizedStandardFlagFallback(answerDisplay); ok {
			if fbSub, fbCorrect, _ := bm.s.m.pg.LookupSubmittedBenchmarkAnswer(ctx, sess.ID, ch.UniqueCode, req.SubFlagID, fbFlag); fbSub && fbCorrect {
				submitted = true
				wasCorrect = true
			}
		}
	}
	if submitted {
		if wasCorrect {
			note := fmt.Sprintf("该阶段 Flag 此前已验证得分（当前进度 %d/%d），请基于已获立足点继续获取其余未完成 Flag", ch.CorrectFlagCount, max(1, ch.FlagCount))
			bm.resolveBenchmarkCTFCandidates(ctx, taskID, answerDisplay, "accepted", note, false)
			return fmt.Sprintf(`{"correct":true,"duplicate":true,"already_accepted":true,"correct_flag_count":%d,"total_flag_count":%d,"message":"该阶段 Flag 此前已验证得分，无需重复提交，请继续向下一阶段推进获取其余 Flag"}`,
				ch.CorrectFlagCount, max(1, ch.FlagCount)), true, nil
		}
		bm.resolveBenchmarkCTFCandidates(ctx, taskID, answerDisplay, "rejected", "该答案此前已向测评平台提交并被判错，切勿重复提交同一答案", false)
		return `{"correct":false,"duplicate":true,"message":"该答案已向测评平台提交并记录，切勿重复提交同一答案"}`, true, nil
	}
	rt, err := bm.runtimeFor(sess)
	if err != nil {
		return "", true, err
	}
	if time.Now().Before(rt.cooldownUntil) {
		wait := time.Until(rt.cooldownUntil)
		if wait > 5*time.Second {
			wait = 5 * time.Second
		}
		select {
		case <-ctx.Done():
			return "", true, ctx.Err()
		case <-time.After(wait):
		}
	}

	res, serr := rt.prov.SubmitAnswer(ctx, req)
	// Retry once on transient transport failure (http_status = 0, no structured API error).
	if serr != nil && (res == nil || (!res.Correct && res.HTTPStatus == 0)) {
		var seCheck *benchmark.StructuredError
		if !errors.As(serr, &seCheck) {
			select {
			case <-ctx.Done():
				return "", true, ctx.Err()
			case <-time.After(500 * time.Millisecond):
			}
			res, serr = rt.prov.SubmitAnswer(ctx, req)
		}
	}
	if res == nil {
		res = &benchmark.SubmitResult{Message: errString(serr)}
	}
	var se *benchmark.StructuredError
	if serr != nil && errors.As(serr, &se) {
		res.HTTPStatus = se.HTTPStatus
		res.Code = se.Code
		res.Message = se.Error()
		res.RetryAfterMs = se.RetryAfterMs
		if se.RetryAfterMs > 0 {
			rt.cooldownUntil = time.Now().Add(time.Duration(se.RetryAfterMs) * time.Millisecond)
		}
	}

	if serr != nil && !res.Correct && res.HTTPStatus == 0 {
		// Never write transport-failed (http_status=0) attempts into benchmark_submissions,
		// otherwise legitimate answers get permanently blocked by duplicate suppression.
		// Still reject the local pending candidate so Worker/Planner are not trapped.
		bm.resolveBenchmarkCTFCandidates(ctx, taskID, answerDisplay, "rejected", "平台网络传输异常（未完成裁决），请调整或重试提交："+serr.Error(), false)
		_ = bm.s.m.pg.AppendBenchmarkEvent(ctx, sess.ID, ch.UniqueCode, "submit_error", serr.Error(), nil)
		return "", true, serr
	}

	// Zero-penalty prefix normalization fallback: if a custom-prefix flag (e.g. SCTF{...})
	// was rejected by the judge, transparently try standard flag{...} once. If accepted,
	// promote the result; if also rejected, do NOT record a second failure row so the
	// 6-rejection circuit breaker is never double-charged.
	recordedAnswer := answerDisplay
	normalizedFrom := ""
	if !res.Correct && strings.TrimSpace(req.Flag) != "" && res.HTTPStatus != http.StatusTooManyRequests && res.Code != "rate_limited" {
		if fbFlag, ok := normalizedStandardFlagFallback(answerDisplay); ok {
			if fbSub, _, _ := bm.s.m.pg.LookupSubmittedBenchmarkAnswer(ctx, sess.ID, ch.UniqueCode, req.SubFlagID, fbFlag); !fbSub {
				fbReq := req
				fbReq.Flag = fbFlag
				if time.Now().Before(rt.cooldownUntil) {
					wait := time.Until(rt.cooldownUntil)
					if wait > 5*time.Second {
						wait = 5 * time.Second
					}
					select {
					case <-ctx.Done():
					case <-time.After(wait):
					}
				}
				fbRes, fbErr := rt.prov.SubmitAnswer(ctx, fbReq)
				var fbSE *benchmark.StructuredError
				if fbErr != nil && errors.As(fbErr, &fbSE) && fbSE.RetryAfterMs > 0 {
					rt.cooldownUntil = time.Now().Add(time.Duration(fbSE.RetryAfterMs) * time.Millisecond)
				}
				if fbRes != nil && fbRes.Correct {
					res = fbRes
					serr = fbErr
					recordedAnswer = fbFlag
					normalizedFrom = answerDisplay
				} else if fbErr == nil || (fbRes != nil && fbRes.HTTPStatus > 0 && fbRes.HTTPStatus != http.StatusTooManyRequests) {
					note := "（已自动尝试标准前缀 flag{...} 亦未通过，请确认 Flag 内容本身）"
					if strings.TrimSpace(res.Message) == "" {
						res.Message = note
					} else {
						res.Message += " " + note
					}
				}
			}
		}
	}

	// Only persist platform-evaluated submissions (or corrected responses) into dedup history.
	if res.HTTPStatus == 0 && res.Correct {
		res.HTTPStatus = 200
	} else if res.HTTPStatus == 0 && serr == nil {
		res.HTTPStatus = 200
	}
	_ = bm.s.m.pg.RecordBenchmarkSubmission(ctx, db.BenchmarkSubmission{
		SessionID:        sess.ID,
		UniqueCode:       ch.UniqueCode,
		SubFlagID:        req.SubFlagID,
		AnswerValue:      recordedAnswer,
		Correct:          res.Correct,
		Awarded:          res.Awarded,
		MatchedFlagIndex: res.MatchedFlagIndex,
		HTTPStatus:       res.HTTPStatus,
		ErrorCode:        res.Code,
		Message:          res.Message,
	})

	newScore := max(ch.CumulativeScore, res.CumulativeScore)
	if res.Correct && res.Awarded > 0 && res.CumulativeScore == 0 {
		newScore = ch.CumulativeScore + res.Awarded
	}
	newCorrectFlags := max(ch.CorrectFlagCount, res.CorrectFlagCount)
	if res.Correct && res.CorrectFlagCount == 0 {
		newCorrectFlags = ch.CorrectFlagCount + 1
	}
	totalFlags := max(ch.FlagCount, res.TotalFlagCount)
	completed := res.Completed || (res.Correct && newCorrectFlags >= max(1, totalFlags))

	_ = bm.s.m.pg.UpdateBenchmarkChallengeProgress(ctx, sess.ID, ch.UniqueCode, newScore, newCorrectFlags, totalFlags, completed)

	if res.Correct {
		bm.mu.Lock()
		if rt.lastFlagAt == nil {
			rt.lastFlagAt = map[string]time.Time{}
		}
		rt.lastFlagAt[ch.UniqueCode] = time.Now()
		bm.mu.Unlock()
		candNote := "平台验证通过"
		if normalizedFrom != "" {
			candNote = fmt.Sprintf("自动归一化前缀 %s -> %s 平台验证通过", normalizedFrom, recordedAnswer)
		}
		if !completed && totalFlags > 1 {
			candNote = fmt.Sprintf("阶段 Flag 验证通过（当前 %d/%d），请继续基于已获立足点获取其余 Flag", newCorrectFlags, totalFlags)
		}
		bm.resolveBenchmarkCTFCandidates(ctx, taskID, answerDisplay, "accepted", candNote, completed)
	} else {
		bm.resolveBenchmarkCTFCandidates(ctx, taskID, answerDisplay, "rejected", "平台验证未通过："+res.Message, false)
	}

	taskIDStr := strconv.FormatInt(taskID, 10)
	if t, ok := bm.s.m.Task(taskIDStr); ok {
		if res.Correct {
			factSummary := fmt.Sprintf("【平台验真通过】%s 得分 +%d（当前 %d/%d Flag）", ch.UniqueCode, res.Awarded, newCorrectFlags, max(1, totalFlags))
			if normalizedFrom != "" {
				factSummary = fmt.Sprintf("【平台验真通过】%s（自动归一化前缀 -> %s）得分 +%d（当前 %d/%d Flag）", ch.UniqueCode, recordedAnswer, res.Awarded, newCorrectFlags, max(1, totalFlags))
			}
			if !completed && totalFlags > 1 {
				factSummary = fmt.Sprintf("【阶段验真通过】%s 得分 +%d（当前 %d/%d Flag，尚余 %d 个未取得；严禁停止或调用 prove_goal 提前结题，请基于当前 Shell/凭据/网络继续推进下一阶段）",
					ch.UniqueCode, res.Awarded, newCorrectFlags, totalFlags, max(0, totalFlags-newCorrectFlags))
			}
			_, _ = t.Store.AddNode("fact", map[string]any{
				"summary":  factSummary,
				"subtype":  "benchmark_verdict",
				"correct":  true,
				"complete": completed,
			}, 0, "confirmed", "benchmark", nil)
		} else {
			_, _ = t.Store.AddNode("fact", map[string]any{
				"summary": fmt.Sprintf("【平台验真拒绝】提交被平台判定错误（%s），严禁重复提交该值，请调整方向", res.Message),
				"subtype": "benchmark_verdict",
				"correct": false,
			}, 0, "confirmed", "benchmark", nil)
		}
		t.Notify()
	}

	if res.Correct {
		_ = bm.s.m.pg.MarkTaskTipsSolved(ctx, taskID)
		evtMsg := fmt.Sprintf("答案通过平台验证（+%d 分，完成=%v）", res.Awarded, completed)
		if normalizedFrom != "" {
			evtMsg = fmt.Sprintf("自动归一化前缀（%s -> %s）通过平台验证（+%d 分，完成=%v）", normalizedFrom, recordedAnswer, res.Awarded, completed)
		}
		_ = bm.s.m.pg.AppendBenchmarkEvent(ctx, sess.ID, ch.UniqueCode, "flag_accepted", evtMsg, res)
		noteText := benchmark.RedactSensitive(fmt.Sprintf("Solved %s (%s), awarded %d score.", ch.UniqueCode, ch.Category, res.Awarded))
		_ = rt.prov.LogNote(ctx, ch.UniqueCode, "solve_summary", noteText)
	} else {
		_ = bm.s.m.pg.AppendBenchmarkEvent(ctx, sess.ID, ch.UniqueCode, "flag_rejected",
			fmt.Sprintf("答案未通过平台验证：%s", res.Message), res)
		if rejCount, rerr := bm.s.m.pg.CountRejectedBenchmarkSubmissions(ctx, sess.ID, ch.UniqueCode); rerr == nil && rejCount > 0 && rejCount%6 == 0 {
			_ = bm.s.m.pg.AppendBenchmarkEvent(ctx, sess.ID, ch.UniqueCode, "flag_retry_limit",
				fmt.Sprintf("题目 %s 当前阶段已被平台连续拒绝 %d 次答案，停止空转并释放并发槽位", ch.UniqueCode, rejCount), nil)
			bm.stopBoundTask(taskIDStr, "failed", fmt.Errorf("平台连续拒绝候选答案达上限 (%d 次)，终止空转释放槽位", rejCount))
			if ch.ContainerStatus == "available" || ch.ContainerStatus == "pending" {
				_ = rt.prov.CloseEnvironment(ctx, ch.UniqueCode)
				_ = bm.s.m.pg.UpdateBenchmarkChallengeEnv(ctx, sess.ID, ch.UniqueCode, "stopped", nil, nil, "")
			}
		}
	}

	if completed {
		bm.stopBoundTask(taskIDStr, "done", errors.New("测评题目已全部通关"))
		if ch.ContainerStatus == "available" || ch.ContainerStatus == "pending" {
			_ = rt.prov.CloseEnvironment(ctx, ch.UniqueCode)
			_ = bm.s.m.pg.UpdateBenchmarkChallengeEnv(ctx, sess.ID, ch.UniqueCode, "stopped", nil, nil, "")
		}
		_ = bm.s.m.pg.AppendBenchmarkEvent(ctx, sess.ID, ch.UniqueCode, "challenge_completed",
			fmt.Sprintf("题目 %s 已全部通关（总计 %d 分）", ch.UniqueCode, newScore), nil)
	} else if res.Correct && totalFlags > 1 {
		res.Message = fmt.Sprintf("阶段 Flag 验证通过（当前进度 %d/%d Flag，尚余 %d 个未获取）；任务尚未完成，严禁结束当前意图！请继续在当前会话与 /work 中基于已获立足点向下一阶段推进",
			newCorrectFlags, totalFlags, max(0, totalFlags-newCorrectFlags))
	} else if res.Correct && normalizedFrom != "" && strings.TrimSpace(res.Message) == "" {
		res.Message = fmt.Sprintf("自动归一化前缀 %s -> %s 验真通过", normalizedFrom, recordedAnswer)
	}

	b, _ := json.Marshal(res)
	return string(b), true, nil
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
