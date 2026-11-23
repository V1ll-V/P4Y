package ctf

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"p3y/ctfrunner"
	"p3y/db"
)

func TestExcerptStripsNULBytes(t *testing.T) {
	raw := []byte("leak=\x00\x7f\xff\xfeok\x00!")
	got := excerpt(raw, 64)
	if strings.ContainsRune(got, 0) {
		t.Fatalf("excerpt retained NUL byte: %q", got)
	}
	if !strings.Contains(got, "leak=") || !strings.Contains(got, "ok!") {
		t.Fatalf("unexpected excerpt output: %q", got)
	}
	trunc := excerpt([]byte("abc\x00defghij"), 4)
	if strings.ContainsRune(trunc, 0) || !strings.Contains(trunc, "[输出节选") {
		t.Fatalf("expected truncated cleaned excerpt, got %q", trunc)
	}
}

func TestSeedNonSharedWorkDirCopiesAssetsSkipsTransientScripts(t *testing.T) {
	root := t.TempDir()
	srcWork := filepath.Join(root, "tasks", "42", "i10", "ctf-work")
	if err := os.MkdirAll(filepath.Join(srcWork, "chall", ".cache"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcWork, "chall", "pwn"), []byte("ELF"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcWork, "solve.py"), []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcWork, "chall", ".cache", "tmp"), []byte("junk"), 0600); err != nil {
		t.Fatal(err)
	}

	targetWork := filepath.Join(root, "tasks", "42", "i11", "ctf-work")
	seedNonSharedWorkDir(root, 42, targetWork)

	if _, err := os.Stat(filepath.Join(targetWork, "chall", "pwn")); err != nil {
		t.Fatalf("expected unpacked asset to be seeded: %v", err)
	}
	if _, err := os.Stat(filepath.Join(targetWork, "solve.py")); !os.IsNotExist(err) {
		t.Fatalf("solve.py should not be seeded across non-shared intents")
	}
}

func TestResolveScopeSharedVsIsolated(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skip("test database required")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()

	root := t.TempDir()
	svc := New(root, pg)

	pwnTask, err := pg.CreateTaskWithOptions("pwn-scope", "goal", db.TaskCreateOptions{Mode: "ctf", ChallengeType: "pwn"})
	if err != nil {
		t.Fatal(err)
	}
	defer pg.DeleteTask(pwnTask.ID)

	si1, wd1, lk1, sh1 := svc.resolveScope(t.Context(), pwnTask.ID, 101)
	si2, wd2, lk2, sh2 := svc.resolveScope(t.Context(), pwnTask.ID, 102)
	if !sh1 || !sh2 || si1 != 0 || si2 != 0 || wd1 != wd2 || lk1 != lk2 {
		t.Fatalf("expected shared Pwn scope across intents: (%d,%s,%s,%v) vs (%d,%s,%s,%v)", si1, wd1, lk1, sh1, si2, wd2, lk2, sh2)
	}

	webTask, err := pg.CreateTaskWithOptions("web-scope", "goal", db.TaskCreateOptions{Mode: "ctf", ChallengeType: "web"})
	if err != nil {
		t.Fatal(err)
	}
	defer pg.DeleteTask(webTask.ID)

	wsi1, wwd1, _, wsh1 := svc.resolveScope(t.Context(), webTask.ID, 201)
	wsi2, wwd2, _, wsh2 := svc.resolveScope(t.Context(), webTask.ID, 202)
	if wsh1 || wsh2 || wsi1 != 201 || wsi2 != 202 || wwd1 == wwd2 {
		t.Fatalf("expected isolated Web scope across intents: (%d,%s,%v) vs (%d,%s,%v)", wsi1, wwd1, wsh1, wsi2, wwd2, wsh2)
	}
}

func TestSharedWorkVolumeAcrossIntentsAndSourceTaskRetries(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skip("test database required")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()

	srcTask, err := pg.CreateTaskWithOptions("web-root", "goal", db.TaskCreateOptions{Mode: "ctf", ChallengeType: "web"})
	if err != nil {
		t.Fatal(err)
	}
	defer pg.DeleteTask(srcTask.ID)

	retryTask, err := pg.CreateTaskWithOptions("web-retry", "goal", db.TaskCreateOptions{
		Mode:          "ctf",
		ChallengeType: "web",
		SourceTaskIDs: []int64{srcTask.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer pg.DeleteTask(retryTask.ID)

	var (
		mu       sync.Mutex
		specs    []ctfrunner.SessionSpec
		putWorks int
	)
	seeded := false
	runnerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/sessions":
			var spec ctfrunner.SessionSpec
			_ = json.NewDecoder(r.Body).Decode(&spec)
			mu.Lock()
			specs = append(specs, spec)
			wasSeeded := seeded
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(ctfrunner.Session{
				Spec:        spec,
				ContainerID: "cid-shared",
				Name:        "p3y-box-" + spec.Key(),
				InputsReady: true,
				WorkSeeded:  wasSeeded,
			})
		case r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/work"):
			mu.Lock()
			putWorks++
			seeded = true
			mu.Unlock()
			w.Write([]byte(`{"ok":true}`))
		default:
			w.WriteHeader(200)
			w.Write([]byte(`{}`))
		}
	}))
	defer runnerSrv.Close()

	svc := New(t.TempDir(), pg)
	svc.BindMount = false
	svc.Runner = &ctfrunner.Client{URL: runnerSrv.URL, Token: strings.Repeat("k", 24)}

	if _, _, _, _, err := svc.prepareSession(t.Context(), srcTask.ID, 101); err != nil {
		t.Fatalf("prepareSession srcTask intent 101: %v", err)
	}
	if _, _, _, _, err := svc.prepareSession(t.Context(), srcTask.ID, 102); err != nil {
		t.Fatalf("prepareSession srcTask intent 102: %v", err)
	}
	if _, _, _, _, err := svc.prepareSession(t.Context(), retryTask.ID, 201); err != nil {
		t.Fatalf("prepareSession retryTask intent 201: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(specs) != 3 {
		t.Fatalf("expected 3 specs, got %d", len(specs))
	}
	for i, sp := range specs {
		wantVol := "p3y-box-task-work-" + strings.TrimSpace(strings.Split(sp.WorkVolume, "p3y-box-task-work-")[1])
		_ = wantVol
		if !strings.HasSuffix(sp.WorkVolume, "-"+strings.TrimLeft(sp.WorkVolume[len("p3y-box-task-work-"):], "")) || !strings.Contains(sp.WorkVolume, "p3y-box-task-work-") {
			t.Fatalf("unexpected WorkVolume on call %d: %q", i, sp.WorkVolume)
		}
	}
	if specs[0].WorkVolume != specs[1].WorkVolume || specs[1].WorkVolume != specs[2].WorkVolume {
		t.Fatalf("expected identical shared WorkVolume across intents & retry task, got %q, %q, %q", specs[0].WorkVolume, specs[1].WorkVolume, specs[2].WorkVolume)
	}
	if putWorks != 1 {
		t.Fatalf("expected PUT /work only once before WorkSeeded=true, got %d", putWorks)
	}
}

func TestSeedNonSharedWorkDirMergesLaterIntentArtifacts(t *testing.T) {
	root := t.TempDir()
	i1 := filepath.Join(root, "tasks", "77", "i1", "ctf-work")
	i2 := filepath.Join(root, "tasks", "77", "i2", "ctf-work")
	if err := os.MkdirAll(i1, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(i2, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(i1, "recon.txt"), []byte("ports:80"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(i1, "cred.json"), []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	oldT := time.Now().Add(-2 * time.Minute)
	_ = os.Chtimes(i1, oldT, oldT)

	if err := os.WriteFile(filepath.Join(i2, "id_rsa"), []byte("KEY"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(i2, "cred.json"), []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}

	target := filepath.Join(root, "tasks", "77", "i3", "ctf-work")
	seedNonSharedWorkDir(root, 77, target)

	if _, err := os.Stat(filepath.Join(target, "recon.txt")); err != nil {
		t.Fatalf("expected i1 artifact: %v", err)
	}
	if _, err := os.Stat(filepath.Join(target, "id_rsa")); err != nil {
		t.Fatalf("expected i2 artifact (not just first non-empty dir): %v", err)
	}
	gotCred, err := os.ReadFile(filepath.Join(target, "cred.json"))
	if err != nil || string(gotCred) != "new" {
		t.Fatalf("expected newer i2 cred.json to win, got %q (%v)", string(gotCred), err)
	}
}

func TestSeedNonSharedWorkDirInheritsNamedScriptsAndAncestors(t *testing.T) {
	root := t.TempDir()
	ancWork := filepath.Join(root, "tasks", "101", "i3", "ctf-work")
	curWork := filepath.Join(root, "tasks", "140", "i1", "ctf-work")
	if err := os.MkdirAll(ancWork, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(curWork, 0700); err != nil {
		t.Fatal(err)
	}
	// Ancestor task (e.g. timed-out round #101) has named scripts + default scratch solve.py
	if err := os.WriteFile(filepath.Join(ancWork, "exp2.py"), []byte("print('v1')"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ancWork, "solve_pow.py"), []byte("pow"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ancWork, "solve.py"), []byte("scratch"), 0600); err != nil {
		t.Fatal(err)
	}
	// Current retry task (#140) intent 1 updated exp2.py and wrote check_rce.py
	if err := os.WriteFile(filepath.Join(curWork, "exp2.py"), []byte("print('v2')"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(curWork, "check_rce.py"), []byte("rce"), 0600); err != nil {
		t.Fatal(err)
	}

	target := filepath.Join(root, "tasks", "140", "i2", "ctf-work")
	seedNonSharedWorkDir(root, 140, target, 101)

	gotExp, err := os.ReadFile(filepath.Join(target, "exp2.py"))
	if err != nil || string(gotExp) != "print('v2')" {
		t.Fatalf("expected current retry task exp2.py (v2) to override ancestor, got %q (%v)", string(gotExp), err)
	}
	if _, err := os.Stat(filepath.Join(target, "solve_pow.py")); err != nil {
		t.Fatalf("expected ancestor named script solve_pow.py to be inherited: %v", err)
	}
	if _, err := os.Stat(filepath.Join(target, "check_rce.py")); err != nil {
		t.Fatalf("expected current task check_rce.py to be inherited: %v", err)
	}
	if _, err := os.Stat(filepath.Join(target, "solve.py")); !os.IsNotExist(err) {
		t.Fatalf("default scratch solve.py should still be skipped")
	}
}

func TestSharedScopeRetryInheritsAncestorWorkAndScriptSnapshotCache(t *testing.T) {
	root := t.TempDir()
	// Ancestor Pwn task (#201) wrote exp.py and patched binary into shared/ctf-work.
	ancShared := filepath.Join(root, "tasks", "201", "shared", "ctf-work")
	if err := os.MkdirAll(ancShared, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ancShared, "exp.py"), []byte("from pwn import *\nprint('pwn_v1')\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ancShared, "chall_patched"), []byte("ELF_PATCHED"), 0700); err != nil {
		t.Fatal(err)
	}

	// Retry Pwn task (#202) prepares its shared/ctf-work directory for the first time.
	retryShared := filepath.Join(root, "tasks", "202", "shared", "ctf-work")
	seedNonSharedWorkDir(root, 202, retryShared, 201)

	gotExp, err := os.ReadFile(filepath.Join(retryShared, "exp.py"))
	if err != nil || !strings.Contains(string(gotExp), "pwn_v1") {
		t.Fatalf("expected Pwn retry shared/ctf-work to inherit ancestor exp.py, got %q (%v)", string(gotExp), err)
	}
	if _, err := os.Stat(filepath.Join(retryShared, "chall_patched")); err != nil {
		t.Fatalf("expected Pwn retry shared/ctf-work to inherit chall_patched: %v", err)
	}

	// Verify incremental snapshotScriptsCached reuses snapshot when unchanged and refreshes on edit.
	svc := &Service{Root: root}
	execDir1 := filepath.Join(root, "tasks", "202", "ctf", "executions", "exec-1")
	execDir2 := filepath.Join(root, "tasks", "202", "ctf", "executions", "exec-2")
	execDir3 := filepath.Join(root, "tasks", "202", "ctf", "executions", "exec-3")
	for _, d := range []string{execDir1, execDir2, execDir3} {
		if err := os.MkdirAll(d, 0700); err != nil {
			t.Fatal(err)
		}
	}
	s1, err := svc.snapshotScriptsCached(202, retryShared, execDir1)
	if err != nil || len(s1) != 1 || s1[0].Name != "exp.py" {
		t.Fatalf("expected 1 snapshotted script in exec-1, got %+v (%v)", s1, err)
	}
	// Second read-only tool execution with no script modification must reuse exec-1 snapshot path without writing to exec-2.
	s2, err := svc.snapshotScriptsCached(202, retryShared, execDir2)
	if err != nil || len(s2) != 1 || s2[0].Path != s1[0].Path || s2[0].SHA256 != s1[0].SHA256 {
		t.Fatalf("expected unchanged /work to reuse cached script snapshot, got s1=%+v s2=%+v", s1, s2)
	}
	if _, err := os.Stat(filepath.Join(execDir2, "script-01.py")); !os.IsNotExist(err) {
		t.Fatalf("expected no duplicate script copy in exec-2 on cache hit")
	}
	// Modifying exp.py must invalidate the signature cache and write a fresh snapshot to exec-3.
	if err := os.WriteFile(filepath.Join(retryShared, "exp.py"), []byte("from pwn import *\nprint('pwn_v2_updated')\n"), 0600); err != nil {
		t.Fatal(err)
	}
	s3, err := svc.snapshotScriptsCached(202, retryShared, execDir3)
	if err != nil || len(s3) != 1 || s3[0].SHA256 == s1[0].SHA256 || !strings.Contains(s3[0].Path, "exec-3") {
		t.Fatalf("expected modified exp.py to produce fresh snapshot in exec-3, got %+v", s3)
	}
}
