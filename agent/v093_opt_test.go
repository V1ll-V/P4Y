package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"p3y/db"
)

func TestRecordFactDedupSupersedesAndOverviewFiltering(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skip("test database required")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()

	task, err := pg.CreateTaskWithOptions("v093-fact-dedup", "get flag", db.TaskCreateOptions{Mode: "ctf", ChallengeType: "web"})
	if err != nil {
		t.Fatal(err)
	}
	defer pg.DeleteTask(task.ID)

	es := pg.Exploration(task.ExplorationID)
	ts := NewToolSet(es, "work#1")
	ts.SetTaskID(task.ID)

	intentID, err := ts.addOneIntent(intentItem{Summary: "probe web", Phase: "exploit"})
	if err != nil {
		t.Fatal(err)
	}
	rawIntent, _ := json.Marshal(intentID)

	// 1. Exact-normalized summary dedup returns existing ID without creating a duplicate node.
	id1, dedup1, err := ts.recordOneFactDetailed(factItem{
		Summary:  "Nginx 拦截小写 /admin，Express 接受 /Admin",
		Detail:   "GET /Admin 返回 200 且进入管理接口，证明存在大小写路由不一致绕过",
		IntentID: rawIntent,
	}, intentID)
	if err != nil || dedup1 || id1 <= 0 {
		t.Fatalf("first record_fact failed: id=%d dedup=%v err=%v", id1, dedup1, err)
	}

	id2, dedup2, err := ts.recordOneFactDetailed(factItem{
		Summary:  "  nginx   拦截小写 /admin，express 接受 /Admin ",
		IntentID: rawIntent,
	}, intentID)
	if err != nil || !dedup2 || id2 != id1 {
		t.Fatalf("expected normalized summary dedup to return %d, got id=%d dedup=%v err=%v", id1, id2, dedup2, err)
	}

	// 2. Identical long detail (>=40 runes) also dedups even with slightly rephrased summary.
	id3, dedup3, err := ts.recordOneFactDetailed(factItem{
		Summary:  "重复汇报同一个路由大小写绕过",
		Detail:   "GET /Admin 返回 200 且进入管理接口，证明存在大小写路由不一致绕过",
		IntentID: rawIntent,
	}, intentID)
	if err != nil || !dedup3 || id3 != id1 {
		t.Fatalf("expected long detail dedup to return %d, got id=%d dedup=%v err=%v", id1, id3, dedup3, err)
	}

	// 3. Superseding an old fact marks it dismissed and removes it from recent_facts.
	oldRef, _ := json.Marshal(id1)
	id4, dedup4, err := ts.recordOneFactDetailed(factItem{
		Summary:           "实测 /Admin 需要管理员 Session，先前判断已更新",
		Detail:            "完整对照实验表明需先 PATCH /ADMIN/api/users/me 修改 role=admin",
		IntentID:          rawIntent,
		SupersedesFactIDs: []json.RawMessage{oldRef},
	}, intentID)
	if err != nil || dedup4 || id4 <= 0 || id4 == id1 {
		t.Fatalf("superseding fact failed: id=%d dedup=%v err=%v", id4, dedup4, err)
	}

	oldNode, err := es.GetNode(id1)
	if err != nil || oldNode == nil || oldNode.State != "dismissed" {
		t.Fatalf("expected superseded fact #%d to be dismissed, got node=%+v err=%v", id1, oldNode, err)
	}

	ov := ts.graphOverviewData()
	recentFacts, _ := ov["recent_facts"].([]map[string]any)
	foundNew := false
	for _, rf := range recentFacts {
		if rf["id"] == id1 {
			t.Fatalf("dismissed fact #%d leaked into recent_facts: %#v", id1, recentFacts)
		}
		if rf["state"] == "origin" {
			t.Fatalf("origin fact should be excluded from CTF recent_facts: %#v", rf)
		}
		if rf["id"] == id4 {
			foundNew = true
		}
	}
	if !foundNew {
		t.Fatalf("expected new confirmed fact #%d in recent_facts, got %#v", id4, recentFacts)
	}
}

func TestGraphOverviewRecentDoneIntentsIncludesTerminalSummaryAndBlockedReason(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skip("test database required")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()

	task, err := pg.CreateTaskWithOptions("v093-done-summary", "get flag", db.TaskCreateOptions{Mode: "ctf", ChallengeType: "reverse"})
	if err != nil {
		t.Fatal(err)
	}
	defer pg.DeleteTask(task.ID)

	es := pg.Exploration(task.ExplorationID)
	ts := NewToolSet(es, "planner")
	ts.SetTaskID(task.ID)

	intentID, err := ts.addOneIntent(intentItem{Summary: "reverse vm lane7", Phase: "exploit"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := es.AppendActivity(db.Activity{
		NodeID:  &intentID,
		Worker:  "work#1",
		Kind:    "result",
		Summary: "已排除 XOR 常量猜测；/work/hook9.so 已就绪，卡点在 word14 自引用分支",
	}); err != nil {
		t.Fatal(err)
	}
	if err := es.SetIntentState(intentID, "exhausted"); err != nil {
		t.Fatal(err)
	}
	if err := es.SetIntentBlockedReason(intentID, "wall-clock budget exhausted"); err != nil {
		t.Fatal(err)
	}

	ov := ts.graphOverviewData()
	doneList, _ := ov["recent_done_intents"].([]map[string]any)
	if len(doneList) == 0 {
		t.Fatalf("expected recent_done_intents to contain exhausted intent #%d", intentID)
	}
	var entry map[string]any
	for _, it := range doneList {
		if it["id"] == intentID {
			entry = it
			break
		}
	}
	if entry == nil {
		t.Fatalf("exhausted intent #%d missing from recent_done_intents: %#v", intentID, doneList)
	}
	if got, _ := entry["blocked_reason"].(string); !strings.Contains(got, "wall-clock budget") {
		t.Fatalf("expected blocked_reason in recent_done_intents, got %#v", entry)
	}
	if got, _ := entry["result_summary"].(string); !strings.Contains(got, "/work/hook9.so") {
		t.Fatalf("expected result_summary in recent_done_intents, got %#v", entry)
	}
}

func TestCryptoMutexDifferentiatedBudgetAndPlannerArtifacts(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skip("test database required")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()

	cryptoTask, err := pg.CreateTaskWithOptions("v093-crypto", "decrypt flag", db.TaskCreateOptions{Mode: "ctf", ChallengeType: "crypto"})
	if err != nil {
		t.Fatal(err)
	}
	defer pg.DeleteTask(cryptoTask.ID)

	webTask, err := pg.CreateTaskWithOptions("v093-web", "pwn web", db.TaskCreateOptions{Mode: "ctf", ChallengeType: "web"})
	if err != nil {
		t.Fatal(err)
	}
	defer pg.DeleteTask(webTask.ID)

	cryptoES := pg.Exploration(cryptoTask.ExplorationID)
	cryptoTS := NewToolSet(cryptoES, "planner")
	cryptoTS.SetTaskID(cryptoTask.ID)

	// 1. Crypto enforces single-thread exploit mutex just like pwn/reverse.
	if _, err := cryptoTS.addOneIntent(intentItem{Summary: "lattice attack", Phase: "exploit"}); err != nil {
		t.Fatalf("first crypto exploit intent failed: %v", err)
	}
	if _, err := cryptoTS.addOneIntent(intentItem{Summary: "parallel helper", Phase: ""}); err == nil {
		t.Fatal("expected parallel helper intent to be rejected while crypto exploit is open")
	}

	// 2. Differentiated wall-clock budget: 30m for crypto, 20m for web, untouched for recon.
	if got := ctfRunBudgetForTask(t.Context(), "", cryptoES, cryptoTask.ID, "exploit", 15*time.Minute); got != 30*time.Minute {
		t.Fatalf("crypto exploit budget = %v, want 30m", got)
	}
	if got := ctfRunBudgetForTask(t.Context(), "", cryptoES, cryptoTask.ID, "recon", 10*time.Minute); got != 10*time.Minute {
		t.Fatalf("crypto recon budget = %v, want 10m preserved", got)
	}
	webES := pg.Exploration(webTask.ExplorationID)
	if got := ctfRunBudgetForTask(t.Context(), "", webES, webTask.ID, "exploit", 15*time.Minute); got != 20*time.Minute {
		t.Fatalf("web exploit budget = %v, want 20m", got)
	}

	// 3. Planner (intentID == 0) also receives /work Top-N artifact listing.
	tmpRoot := t.TempDir()
	workDir := filepath.Join(tmpRoot, "tasks", strconv.FormatInt(cryptoTask.ID, 10), "i1", "ctf-work")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workDir, "exp.py"), []byte("print('ready')\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	plannerCtx, err := taskInputContextForRole(tmpRoot, cryptoES, cryptoTask.ID, 0, "planner")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plannerCtx, "/work 已有产物") || !strings.Contains(plannerCtx, "exp.py") {
		t.Fatalf("expected planner context to include /work artifacts listing, got:\n%s", plannerCtx)
	}
}
