package agent

import (
	"context"
	"encoding/json"
	"p3y/ctf"
	"p3y/db"
	actool "github.com/Autumn-27/norma/tool"
	"strings"
	"testing"
)

func TestCTFFileToolsRejectApplicationPaths(t *testing.T) {
	for _, tool := range ctfTools(nil, 1, 1, "") {
		if tool.Name() != "Read" && tool.Name() != "Write" && tool.Name() != "Edit" && tool.Name() != "Grep" && tool.Name() != "Glob" && tool.Name() != "LS" {
			continue
		}
		for _, p := range []string{"/app/config.json", "/var/run/docker.sock", "/work/../../app/jwt.key"} {
			in, _ := json.Marshal(map[string]any{"path": p, "file_path": p, "content": "x", "old_string": "a", "new_string": "b", "pattern": "flag"})
			result, err := tool.Call(t.Context(), in, nil)
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := json.Marshal(result)
			if !strings.Contains(string(raw), "仅允许") {
				t.Fatalf("%s allowed %s: %s", tool.Name(), p, raw)
			}
		}
	}
}

func TestCTFEditRejectsInputsAndValidatesArgs(t *testing.T) {
	var editTool, grepTool, globTool actool.CoreTool
	for _, tl := range ctfTools(nil, 1, 1, "") {
		switch tl.Name() {
		case "Edit":
			editTool = tl
		case "Grep":
			grepTool = tl
		case "Glob":
			globTool = tl
		}
	}
	if editTool == nil || grepTool == nil || globTool == nil {
		t.Fatalf("missing new file tools: edit=%v grep=%v glob=%v", editTool != nil, grepTool != nil, globTool != nil)
	}
	for _, tc := range []struct {
		name string
		tl   actool.CoreTool
		args map[string]any
		want string
	}{
		{"edit_inputs", editTool, map[string]any{"file_path": "/work/.inputs/chall", "old_string": "a", "new_string": "b"}, "只读"},
		{"edit_empty_old", editTool, map[string]any{"file_path": "/work/exp.py", "old_string": "", "new_string": "b"}, "不能为空"},
		{"edit_same", editTool, map[string]any{"file_path": "/work/exp.py", "old_string": "same", "new_string": "same"}, "相同"},
		{"grep_empty_pat", grepTool, map[string]any{"pattern": "   "}, "不能为空"},
		{"glob_empty_pat", globTool, map[string]any{"pattern": ""}, "不能为空"},
	} {
		in, _ := json.Marshal(tc.args)
		res, err := tc.tl.Call(t.Context(), in, nil)
		if err != nil {
			t.Fatalf("%s err: %v", tc.name, err)
		}
		raw, _ := json.Marshal(res)
		if !strings.Contains(string(raw), tc.want) {
			t.Fatalf("%s expected %q, got %s", tc.name, tc.want, raw)
		}
	}
}
func TestCTFAssemblyCannotAcquireHostShell(t *testing.T) {
	oldAugment, oldResolve := ToolAugment, ToolResolve
	defer func() { ToolAugment, ToolResolve = oldAugment, oldResolve }()
	called := false
	ToolAugment = func(context.Context, string) ([]actool.CoreTool, DeferredInfo, func()) {
		called = true
		return nil, DeferredInfo{}, func() {}
	}
	ToolResolve = func(_ context.Context, _ string, base []actool.CoreTool) []actool.CoreTool {
		return append(base, readTool("shell_open", "host shell", obj(nil), nil))
	}
	ctx := context.WithValue(t.Context(), ctfRunKey{}, true)
	base := ctfTools(nil, 1, 1, "")
	tools, _, cleanup := AugmentTools(ctx, "worker", base)
	defer cleanup()
	if called {
		t.Fatal("CTF attached host MCPs")
	}
	for _, tool := range tools {
		if tool.Name() == "shell_open" {
			t.Fatal("host shell injected into CTF")
		}
	}
}

func TestCTFBaseForPlannerStripsExecutionTools(t *testing.T) {
	base := []actool.CoreTool{
		readTool("Bash", "bash", obj(nil), nil),
		readTool("Read", "read", obj(nil), nil),
		readTool("LS", "ls", obj(nil), nil),
		readTool("ctf_python", "py", obj(nil), nil),
		readTool("ctf_http", "http", obj(nil), nil),
		readTool("sleep", "sleep", obj(nil), nil),
		readTool("graph_overview", "overview", obj(nil), nil),
		readTool("add_intent", "add intent", obj(nil), nil),
		readTool("record_fact", "record fact", obj(nil), nil),
	}
	filtered := stripCTFPlannerBase(base)
	names := make(map[string]bool, len(filtered))
	for _, tl := range filtered {
		names[tl.Name()] = true
	}
	if !names["add_intent"] {
		t.Fatal("expected add_intent to be preserved for CTF planner")
	}
	for _, forbidden := range []string{"Bash", "Read", "LS", "sleep", "graph_overview", "ctf_python", "ctf_http", "ctf_pcap"} {
		if names[forbidden] {
			t.Fatalf("expected execution tool %s to be stripped from CTF planner", forbidden)
		}
	}
	ctxOut, nilOut := ctfBaseForPlanner(t.Context(), nil, base)
	if ctxOut == nil || len(nilOut) != len(base) {
		t.Fatalf("expected nil store fallback to preserve base tools, got %d", len(nilOut))
	}
}

func TestCTFIntentPhaseAndPlannerStrategy(t *testing.T) {
	if got := intentPhase(&db.Node{Payload: json.RawMessage(`{"summary":"probe","phase":" Recon "}`)}); got != "recon" {
		t.Fatalf("expected recon phase, got %q", got)
	}
	if got := intentPhase(&db.Node{Payload: json.RawMessage(`{"summary":"plain"}`)}); got != "" {
		t.Fatalf("expected empty phase, got %q", got)
	}
	if got := ctfMaxTurnsForPhase(true, "recon", 0); got != 16 {
		t.Fatalf("expected recon maxTurns capped at 16, got %d", got)
	}
	if got := ctfMaxTurnsForPhase(true, "recon", 10); got != 10 {
		t.Fatalf("expected lower configured maxTurns preserved, got %d", got)
	}
	if got := ctfMaxTurnsForPhase(true, "exploit", 0); got != 0 {
		t.Fatalf("expected exploit maxTurns preserved, got %d", got)
	}
	pwnHint := ctfPlannerStrategyHint("pwn")
	if !strings.Contains(pwnHint, "动静合一") || !strings.Contains(pwnHint, "recon") {
		t.Fatalf("expected pwn planner hint to mention unified static/dynamic and recon phase, got %q", pwnHint)
	}
	webHint := ctfPlannerStrategyHint("web")
	if !strings.Contains(webHint, "并行") {
		t.Fatalf("expected web planner hint to mention parallel exploration, got %q", webHint)
	}
}

func TestCTFPwnTriageToolRegistered(t *testing.T) {
	found := false
	for _, tl := range ctfCatalogTools() {
		if tl.Name() == "ctf_pwn_triage" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected ctf_pwn_triage to be registered in ctfCatalogTools")
	}
	inExec := false
	for _, name := range ctfExecutionTools {
		if name == "ctf_pwn_triage" {
			inExec = true
			break
		}
	}
	if !inExec {
		t.Fatal("expected ctf_pwn_triage in ctfExecutionTools")
	}
}

func TestCTFGraphOverviewPausedAndPwnExploitMutex(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skip("test database required")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()

	task, err := pg.CreateTaskWithOptions("pwn-planner-mutex", "goal", db.TaskCreateOptions{Mode: "ctf", ChallengeType: "pwn"})
	if err != nil {
		t.Fatal(err)
	}
	defer pg.DeleteTask(task.ID)

	es := pg.Exploration(task.ExplorationID)
	ts := NewToolSet(es, "planner")
	ts.SetTaskID(task.ID)

	// 尚无 exploit 意图前，允许派发 phase="recon"
	reconID, err := ts.addOneIntent(intentItem{Summary: "light recon", Phase: "recon"})
	if err != nil || reconID <= 0 {
		t.Fatalf("add recon before exploit failed: id=%d err=%v", reconID, err)
	}

	id1, err := ts.addOneIntent(intentItem{Summary: "main exploit", Phase: "exploit"})
	if err != nil || id1 <= 0 {
		t.Fatalf("add first exploit failed: id=%d err=%v", id1, err)
	}
	// 第二条在首条 open 时必须拒绝（无论 phase="exploit" 还是空 phase="" 的辅助意图）
	if _, err = ts.addOneIntent(intentItem{Summary: "dup exploit", Phase: "exploit"}); err == nil {
		t.Fatal("expected second exploit intent to be rejected while first is open")
	}
	if _, err = ts.addOneIntent(intentItem{Summary: "parallel helper bypass", Phase: ""}); err == nil {
		t.Fatal("expected empty-phase helper intent to be rejected while exploit is open")
	}
	// 模拟用户暂停第一条主攻意图
	if _, err = pg.Exec(`UPDATE exploration_nodes SET state='paused', owner='work#1' WHERE id=$1`, id1); err != nil {
		t.Fatal(err)
	}
	ov := ts.graphOverviewData()
	pausedCount, _ := ov["paused_intents_total"].(int)
	if pausedCount != 1 {
		t.Fatalf("expected paused_intents_total=1 in graphOverviewData, got %#v", ov["paused_intents_total"])
	}
	if _, err = ts.addOneIntent(intentItem{Summary: "dup while paused", Phase: "exploit"}); err == nil {
		t.Fatal("expected second exploit intent to be rejected while first is paused")
	}
	if _, err = ts.addOneIntent(intentItem{Summary: "helper while paused", Phase: ""}); err == nil {
		t.Fatal("expected empty-phase helper intent to be rejected while exploit is paused")
	}
	// 第一条明确 exhausted 后应允许续派一条主攻意图
	if _, err = pg.Exec(`UPDATE exploration_nodes SET state='exhausted' WHERE id=$1`, id1); err != nil {
		t.Fatal(err)
	}
	id2, err := ts.addOneIntent(intentItem{Summary: "resume exploit", Phase: "exploit"})
	if err != nil || id2 <= 0 {
		t.Fatalf("expected exploit intent allowed after exhaustion, got id=%d err=%v", id2, err)
	}
}

func TestCTFDomainToolpacksAndWebSkillUnlock(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skip("test database required")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()

	webTask, err := pg.CreateTaskWithOptions("web-pack", "flag", db.TaskCreateOptions{Mode: "ctf", ChallengeType: "web"})
	if err != nil {
		t.Fatal(err)
	}
	defer pg.DeleteTask(webTask.ID)

	oldAugment, oldResolve := ToolAugment, ToolResolve
	defer func() { ToolAugment, ToolResolve = oldAugment, oldResolve }()

	ToolAugment = func(context.Context, string) ([]actool.CoreTool, DeferredInfo, func()) {
		extra := []actool.CoreTool{
			readTool("Skill", "skill loader", obj(nil), nil),
			readTool("mcp__playwright__navigate", "pw", obj(nil), nil),
			readTool("mcp__host_shell__exec", "host shell mcp", obj(nil), nil),
			readTool("Bash", "host bash", obj(nil), nil),
		}
		def := DeferredInfo{
			Deferred:    []string{"mcp__playwright__navigate", "mcp__host_shell__exec", "Bash"},
			GlobalNames: []string{"mcp__playwright__navigate", "mcp__host_shell__exec", "Bash"},
			Unlock:      actool.NewUnlockSet("mcp__playwright__navigate"),
		}
		return extra, def, nil
	}
	ToolResolve = nil

	root := t.TempDir()
	ctx, base := ctfBase(t.Context(), root, pg.Exploration(webTask.ExplorationID), webTask.ID, 1, nil)
	tools, def, cleanup := AugmentTools(ctx, "worker", base)
	defer cleanup()

	mounted := map[string]actool.CoreTool{}
	for _, tl := range tools {
		mounted[tl.Name()] = tl
	}
	if mounted["Skill"] == nil || mounted["mcp__playwright__navigate"] == nil || mounted["ctf_http"] == nil || mounted["Edit"] == nil {
		t.Fatalf("expected Skill, playwright MCP, ctf_http, Edit mounted for web task; got keys=%v", len(mounted))
	}
	if mounted["http_send"] != nil || mounted["ctf_python"] != nil {
		t.Fatal("redundant http_send / ctf_python must not be mounted in CTF worker tools")
	}
	if mounted["mcp__host_shell__exec"] != nil {
		t.Fatal("host shell MCP must remain blocked in web CTF")
	}
	deferredSet := map[string]bool{}
	for _, n := range def.Deferred {
		deferredSet[n] = true
	}
	for _, wantDef := range []string{"ctf_decompile", "ctf_pwn_triage", "ctf_gdb", "ctf_pcap_analyze"} {
		if !deferredSet[wantDef] {
			t.Fatalf("expected non-web tool %s to be deferred on web task", wantDef)
		}
	}
	if deferredSet["ctf_http"] || deferredSet["Bash"] || deferredSet["Edit"] {
		t.Fatalf("web/base tools must not be deferred: %v", def.Deferred)
	}
	for _, n := range def.GlobalNames {
		if n == "mcp__host_shell__exec" || n == "Bash" {
			t.Fatalf("unsafe deferred name leaked into GlobalNames: %s", n)
		}
	}
	if def.Unlock.Has("ctf_decompile") {
		t.Fatal("binary tool should start locked on web task")
	}
	unlockTool := mounted["ctf_unlock_toolpack"]
	if unlockTool == nil {
		t.Fatal("expected ctf_unlock_toolpack in Base Pack")
	}
	in, _ := json.Marshal(map[string]string{"pack": "binary"})
	if _, err := unlockTool.Call(ctx, in, nil); err != nil {
		t.Fatalf("ctf_unlock_toolpack call failed: %v", err)
	}
	if !def.Unlock.Has("ctf_decompile") || !def.Unlock.Has("ctf_pwn_triage") {
		t.Fatal("expected binary pack tools to be unlocked in shared UnlockSet")
	}
}

func TestRenderIntentSecondaryTipsRecallsWithoutDupOrHitBump(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skip("postgres test database required")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()

	ctx := t.Context()
	cLFI, err := pg.CreateTipCard(ctx, db.TipCard{
		Category:    "web",
		Tags:        []string{"web", "lfi", "filter_chain", "kit"},
		Title:       "[KIT] Dynamic Test LFI Filter Chain",
		Pitfall:     "Use php_filter_chain_generator for blind include",
		PatternCode: "python3 /opt/ctf/kits/php_filter_chain_generator.py --chain '<?php id; ?>'",
	})
	if err != nil {
		t.Fatal(err)
	}
	cPhase0, err := pg.CreateTipCard(ctx, db.TipCard{
		Category:    "web",
		Tags:        []string{"web", "session", "kit"},
		Title:       "[KIT] Phase0 Already Shown Card",
		Pitfall:     "Already injected by Phase-0 precheck",
		PatternCode: "session_inject.py",
	})
	if err != nil {
		t.Fatal(err)
	}
	cExcluded, err := pg.CreateTipCard(ctx, db.TipCard{
		Category:    "web",
		Tags:        []string{"web", "handlebars", "ssti"},
		Title:       "[KIT] Excluded Orthogonal Card",
		Pitfall:     "Must NOT be recalled when excluded in parens",
		PatternCode: "exp_render.py",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = pg.DeleteTipCard(context.Background(), cLFI.ID)
		_ = pg.DeleteTipCard(context.Background(), cPhase0.ID)
		_ = pg.DeleteTipCard(context.Background(), cExcluded.ID)
	})

	task, err := pg.CreateTaskWithOptions("secondary-recall-test", "Explore web target", db.TaskCreateOptions{
		Mode:          "ctf",
		ChallengeType: "web",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pg.DeleteTask(task.ID) })

	// Save Phase-0 Precheck containing cPhase0 so secondary recall must deduplicate it.
	preRaw, _ := json.Marshal(ctf.PrecheckResult{
		TaskID:           task.ID,
		InferredCategory: "web",
		MatchedTips:      []db.TipCard{*cPhase0},
	})
	if err := pg.SaveTaskPrecheck(ctx, task.ID, preRaw); err != nil {
		t.Fatal(err)
	}

	ts := pg.Exploration(task.ExplorationID)
	intent := &db.Node{
		ID: 42,
		Payload: json.RawMessage(`{
			"summary": "利用 services.php LFI 与 php://filter 拿 RCE，同时复用 session_inject（已排除 Handlebars SSTI，与此前正交不重复）",
			"target": "http://10.0.181.184/services.php?lang=en"
		}`),
	}

	rendered := renderIntentSecondaryTips(ctx, ts, task.ID, intent)
	if !strings.Contains(rendered, "Dynamic Test LFI Filter Chain") {
		t.Fatalf("expected LFI card recalled in secondary tips, got:\n%s", rendered)
	}
	if strings.Contains(rendered, "Phase0 Already Shown Card") {
		t.Fatalf("expected Phase-0 shown card deduplicated, got:\n%s", rendered)
	}
	if strings.Contains(rendered, "Excluded Orthogonal Card") {
		t.Fatalf("expected orthogonal/excluded Handlebars card NOT recalled, got:\n%s", rendered)
	}

	// Verify read-only lookup did not bump hit_count on cLFI.
	cards, err := pg.ListTips(ctx, "web", 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cards {
		if c.ID == cLFI.ID && c.HitCount != 0 {
			t.Fatalf("expected read-only secondary recall not to bump HitCount, got %d", c.HitCount)
		}
	}
}

func TestParallelAskHelperAndDeterministicCriticAndGraphDenoise(t *testing.T) {
	// 1. Lead-Solver floor in ctfMaxTurnsForPhase
	if got := ctfMaxTurnsForPhase(true, "exploit", 24); got != 80 {
		t.Fatalf("expected exploit phase maxTurns floor 80, got %d", got)
	}
	if got := ctfMaxTurnsForPhase(true, "exploit", 96); got != 96 {
		t.Fatalf("expected exploit phase maxTurns 96 preserved, got %d", got)
	}

	// 2. Parallel ask_helper(tasks=[...]) fan-out
	tl := askHelperTool()
	ctx := WithCTFHelperRunner(t.Context(), func(_ context.Context, req CTFHelperRequest) (CTFHelperResult, error) {
		return CTFHelperResult{
			Summary:       "done:" + req.Goal,
			FocusPath:     req.FocusPath,
			FactsRecorded: 1,
		}, nil
	})
	rawIn := json.RawMessage(`{
		"tasks": [
			{"name": "route_a", "goal": "audit /api/login", "focus_path": "/work/app"},
			{"name": "route_b", "goal": "audit /api/admin", "focus_path": "/work/admin"},
			{"name": "crypto_c", "goal": "recover jwt secret"}
		]
	}`)
	res, err := tl.Call(ctx, rawIn, nil)
	if err != nil || res.IsError {
		t.Fatalf("parallel ask_helper failed: res=%+v err=%v", res, err)
	}
	var batch CTFHelperBatchResult
	if len(res.Content) == 0 {
		t.Fatal("expected non-empty content block from parallel ask_helper")
	}
	if err := json.Unmarshal([]byte(res.Content[0].Text), &batch); err != nil {
		t.Fatalf("unmarshal batch result: %v (%s)", err, res.Content[0].Text)
	}
	if batch.Mode != "parallel" || batch.Count != 3 || len(batch.Results) != 3 {
		t.Fatalf("expected 3 parallel helper results, got %+v", batch)
	}
	if batch.Results[0].Name != "route_a" || batch.Results[1].Summary != "done:audit /api/admin" {
		t.Fatalf("unexpected parallel helper result ordering/content: %+v", batch.Results)
	}

	// 3. Zero-LLM deterministic Critic advice across failure classes
	hooks := newCTFCriticHooks(nil, nil, nil, 0, 0, nil)
	for i := 0; i < 3; i++ {
		hooks.PostToolUse(t.Context(), "Bash", []byte(`{"command":"python3 exp.py"}`), []byte(`{"exit_code":139,"stderr":"Segmentation fault (core dumped)"}`), false)
	}
	blocked, msg, _ := hooks.PreToolUse(t.Context(), "Bash", []byte(`{"command":"python3 exp.py"}`))
	if !blocked || !strings.Contains(msg, "MOVAPS") || !strings.Contains(msg, "diff_local_remote") {
		t.Fatalf("expected 0-LLM deterministic crash/MOVAPS advice on 3rd segfault, got blocked=%v msg=%q", blocked, msg)
	}

	// 4. CTF Graph Overview denoising
	sampleOverview := map[string]any{
		"goals":                     []string{"get flag"},
		"facts":                     2,
		"recent_facts":              []map[string]any{{"id": 1, "summary": "precheck", "detail": "ELF 64-bit", "evidence": "NX enabled"}},
		"findings_total":            0,
		"candidates_total":          0,
		"finding_list":              []any{},
		"awaiting_goal_evaluations": 0,
		"coverage":                  map[string]any{"host_count": 0},
		"paused_intents_total":      0,
	}
	rendered := renderWorkerGraphOverview(sampleOverview, true)
	for _, banned := range []string{"findings_total", "candidates_total", "finding_list", "awaiting_goal_evaluations", "coverage"} {
		if strings.Contains(rendered, banned) {
			t.Fatalf("expected CTF graph overview to strip enterprise field %q, got:\n%s", banned, rendered)
		}
	}
	if !strings.Contains(rendered, "ELF 64-bit") || !strings.Contains(rendered, "paused_intents_total") {
		t.Fatalf("expected inline fact detail and paused_intents_total retained, got:\n%s", rendered)
	}
}
