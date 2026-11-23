package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"p3y/db"
	"github.com/Autumn-27/norma/llm"
)

type spyHooks struct {
	preCalls int
}

func (s *spyHooks) PreToolUse(context.Context, string, []byte) (bool, string, []byte) {
	s.preCalls++
	return false, "", nil
}
func (s *spyHooks) PostToolUse(context.Context, string, []byte, []byte, bool) {}
func (s *spyHooks) Stop(context.Context, []llm.Message) (bool, []string, string) {
	return false, nil, ""
}

func TestCTFTargetScopeGuardBlocksCrossChallengeAndAllowsLegitimateWork(t *testing.T) {
	guard := newCTFTargetScopeGuard(
		[]string{"10.0.178.80"},
		[]string{"10.0.178.81"},
		nil,
	)
	if guard == nil {
		t.Fatal("expected non-nil scope guard")
	}
	if blk := guard.RenderPromptBlock(); !strings.Contains(blk, "10.0.178.80") || !strings.Contains(blk, "10.0.178.0/24") {
		t.Fatalf("unexpected prompt block: %q", blk)
	}

	// Must block Level 1 sibling IP and Level 2 same-/24 unknown IP + CIDR sweeps.
	blockedCases := []struct {
		name  string
		tool  string
		input map[string]any
	}{
		{"ctf_http sibling", "ctf_http", map[string]any{"url": "http://10.0.178.81/admin/login.php"}},
		{"ctf_probe unknown same /24", "ctf_probe_target", map[string]any{"target": "10.0.178.192:8080"}},
		{"bash cidr /24 sweep", "Bash", map[string]any{"command": "nmap -p 80,8080 10.0.178.0/24"}},
		{"bash cidr /18 sweep", "Bash", map[string]any{"command": "python3 -c 'import ipaddress; print(list(ipaddress.ip_network(\"10.0.128.0/18\")))'"}},
		{"write python sweep loop", "Write", map[string]any{"file_path": "/work/wide_sweep.py", "content": "for i in range(1,255):\n    u = f'http://10.0.178.{i}:8080'\n"}},
		{"write python sibling url", "Write", map[string]any{"file_path": "/work/admin_exp.py", "content": "import requests\nrequests.get('http://10.0.178.81/admin')\n"}},
		{"bash curl unknown same /24", "Bash", map[string]any{"command": "curl -s http://10.0.178.192:8080/preview"}},
	}
	for _, tc := range blockedCases {
		raw, _ := json.Marshal(tc.input)
		blocked, msg := guard.CheckToolCall(tc.tool, raw)
		if !blocked || !strings.Contains(msg, "越界硬拦截") {
			t.Fatalf("case %q: expected block, got blocked=%v msg=%q", tc.name, blocked, msg)
		}
	}

	// Must allow own target, internal Docker/pivot subnets, notes, comments, and host interface masks.
	allowedCases := []struct {
		name  string
		tool  string
		input map[string]any
	}{
		{"ctf_http own target", "ctf_http", map[string]any{"url": "http://10.0.178.80/services.php?lang=en"}},
		{"ctf_probe internal docker", "ctf_probe_target", map[string]any{"target": "172.18.0.3:8080"}},
		{"bash relay on own target", "Bash", map[string]any{"command": "sshpass -p x ssh -p 12346 admin@10.0.178.80"}},
		{"bash internal subnet scan via webshell", "Bash", map[string]any{"command": "python3 exp.py 'for i in 2 3 4; do curl -s http://172.18.0.$i:8080; done'"}},
		{"write notes mentioning sibling", "Write", map[string]any{"file_path": "/work/notes.md", "content": "10.0.178.81 is another challenge; ignore 10.0.178.0/24"}},
		{"write script with comment and host mask", "Write", map[string]any{"file_path": "/work/exp.py", "content": "# eth0 10.0.178.80/18, ignore 10.0.178.81\nimport requests\nrequests.get('http://10.0.178.80/')\n"}},
		{"record_fact never blocked", "record_fact", map[string]any{"summary": "confirmed 10.0.178.81 is separate"}},
		{"read never blocked", "Read", map[string]any{"file_path": "/work/notes.md"}},
	}
	for _, tc := range allowedCases {
		raw, _ := json.Marshal(tc.input)
		if blocked, msg := guard.CheckToolCall(tc.tool, raw); blocked {
			t.Fatalf("case %q: unexpected block: %q", tc.name, msg)
		}
	}

	// Explicit CIDR in challenge description disables Level 2 /24 guard while preserving Level 1 sibling block.
	openCIDRGuard := newCTFTargetScopeGuard([]string{"10.0.178.80"}, []string{"10.0.178.81"}, []string{"10.0.178.0/24"})
	if openCIDRGuard == nil {
		t.Fatal("expected guard to remain active for Level 1 sibling IP")
	}
	if blocked, _ := openCIDRGuard.CheckToolCall("ctf_http", []byte(`{"url":"http://10.0.178.192:8080/"}`)); blocked {
		t.Fatal("explicit CIDR in description should allow non-sibling IP in that CIDR")
	}
	if blocked, _ := openCIDRGuard.CheckToolCall("ctf_http", []byte(`{"url":"http://10.0.178.81/"}`)); !blocked {
		t.Fatal("Level 1 sibling challenge IP must still be blocked")
	}

	// Hook wrapper short-circuits before inner hooks (so Critic counter is untouched).
	spy := &spyHooks{}
	hooks := ctfScopeGuardHooks{inner: spy, guard: guard}
	if blocked, _, _ := hooks.PreToolUse(t.Context(), "ctf_http", []byte(`{"url":"http://10.0.178.81/"}`)); !blocked {
		t.Fatal("expected hook to block sibling IP")
	}
	if spy.preCalls != 0 {
		t.Fatalf("expected inner hooks not called on scope block, got preCalls=%d", spy.preCalls)
	}
}

func TestBenchmarkTaskTargetScopeDBResolution(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skip("test database required")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()

	// Manual non-benchmark task must return nil guard (no-op).
	manualTask, err := pg.CreateTaskWithOptions("manual-open-range", "scan 10.0.178.0/24", db.TaskCreateOptions{Mode: "ctf", ChallengeType: "web"})
	if err != nil {
		t.Fatal(err)
	}
	defer pg.DeleteTask(manualTask.ID)
	if g := resolveCTFTargetScopeGuard(t.Context(), pg, manualTask.ID); g != nil {
		t.Fatalf("expected nil scope guard for non-benchmark task, got %+v", g)
	}

	// Benchmark session with two sibling challenges on same /24.
	sess, err := pg.CreateBenchmarkSession(t.Context(), db.BenchmarkSessionCreate{
		Name:     "scope-guard-test",
		Provider: "ctf2",
		BaseURL:  "http://127.0.0.1:9999",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer pg.DeleteBenchmarkSession(t.Context(), sess.ID)

	t1, err := pg.CreateTaskWithOptions("bench-b01", "goal", db.TaskCreateOptions{Mode: "ctf", ChallengeType: "web"})
	if err != nil {
		t.Fatal(err)
	}
	defer pg.DeleteTask(t1.ID)
	t2, err := pg.CreateTaskWithOptions("bench-b02", "goal", db.TaskCreateOptions{Mode: "ctf", ChallengeType: "web"})
	if err != nil {
		t.Fatal(err)
	}
	defer pg.DeleteTask(t2.ID)

	if err := pg.SyncBenchmarkChallenges(t.Context(), sess.ID, []db.BenchmarkChallengeUpsert{
		{UniqueCode: "b-01", Title: "b-01", Description: "portal", ContainerStatus: "available", ContainerAddr: []string{"10.0.178.80:80"}},
		{UniqueCode: "b-02", Title: "b-02", Description: "oa", ContainerStatus: "available", ContainerAddr: []string{"10.0.178.81:80"}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := pg.BindBenchmarkChallengeTask(t.Context(), sess.ID, "b-01", t1.ID); err != nil {
		t.Fatal(err)
	}
	if err := pg.BindBenchmarkChallengeTask(t.Context(), sess.ID, "b-02", t2.ID); err != nil {
		t.Fatal(err)
	}

	g1 := resolveCTFTargetScopeGuard(t.Context(), pg, t1.ID)
	if g1 == nil {
		t.Fatal("expected scope guard for benchmark task b-01")
	}
	if blocked, _ := g1.CheckToolCall("ctf_http", []byte(`{"url":"http://10.0.178.80/"}`)); blocked {
		t.Fatal("b-01 must allow its own target 10.0.178.80")
	}
	if blocked, msg := g1.CheckToolCall("ctf_http", []byte(`{"url":"http://10.0.178.81/"}`)); !blocked || !strings.Contains(msg, "另一道无关赛题") {
		t.Fatalf("b-01 must block sibling b-02 (10.0.178.81) as Level 1, got blocked=%v msg=%q", blocked, msg)
	}
	if blocked, _ := g1.CheckToolCall("ctf_http", []byte(`{"url":"http://10.0.178.192:8080/"}`)); !blocked {
		t.Fatal("b-01 must block unknown same-/24 target 10.0.178.192")
	}
}
