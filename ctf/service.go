// Package ctf binds task inputs, isolated executions, evidence and write-ups.
package ctf

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"p3y/artifacts"
	"p3y/ctfrunner"
	"p3y/db"
	"github.com/google/uuid"
)

type Service struct {
	Root        string
	DB          *db.DB
	Runner      *ctfrunner.Client
	BindMount   bool
	HostRoot    string
	ProxyAddr   string
	ProxyCACert string
}

// BenchmarkFlagHook is registered by the server to auto-submit captured or explicit
// CTF candidate flags on zero-touch benchmark tasks.
var BenchmarkFlagHook func(ctx context.Context, taskID int64, execID, value, subFlagID string) (verdictJSON string, handled bool, err error)

func New(root string, pg *db.DB) *Service {
	runner := &ctfrunner.Client{URL: os.Getenv("P3Y_BOX_URL"), Token: os.Getenv("P3Y_BOX_TOKEN")}
	bindMount := os.Getenv("P3Y_BOX_BIND_MOUNT") == "1"
	if ctfrunner.LocalModeEnabled() {
		runner = ctfrunner.DefaultLocalClient()
		bindMount = true
	}
	return &Service{
		Root:      root,
		DB:        pg,
		Runner:    runner,
		BindMount: bindMount,
		HostRoot:  strings.TrimSpace(os.Getenv("P3Y_BOX_HOST_ROOT")),
	}
}

// IsLocalSandbox reports whether CTF executions use the in-process LocalBackend.
func (s *Service) IsLocalSandbox() bool {
	return s != nil && ctfrunner.IsLocalClient(s.Runner)
}

// TranslateSandboxWorkPaths rewrites standalone /work references inside script or
// file contents to the isolated per-session directory when running in local mode.
func (s *Service) TranslateSandboxWorkPaths(ctx context.Context, task, intent int64, raw string) string {
	if !s.IsLocalSandbox() || !strings.Contains(raw, "/work") {
		return raw
	}
	key, _, err := s.sessionKey(ctx, task, intent)
	if err != nil || key == "" {
		return raw
	}
	return ctfrunner.RewriteWorkPaths(raw, ctfrunner.LocalWorkAlias(s.Runner, key))
}

// WithProxy configures the host MITM traffic proxy passed into sandbox containers.
func (s *Service) WithProxy(addr, caCert string) *Service {
	if s == nil {
		return nil
	}
	s.ProxyAddr = strings.TrimSpace(addr)
	s.ProxyCACert = strings.TrimSpace(caCert)
	return s
}

func (s *Service) bindMountEnabled() bool {
	return s != nil && (s.BindMount || os.Getenv("P3Y_BOX_BIND_MOUNT") == "1")
}

func (s *Service) hostBindPath(localPath string) string {
	hostRoot := strings.TrimSpace(s.HostRoot)
	if hostRoot == "" {
		hostRoot = strings.TrimSpace(os.Getenv("P3Y_BOX_HOST_ROOT"))
	}
	if hostRoot == "" || s.Root == "" {
		return localPath
	}
	rel, err := filepath.Rel(s.Root, localPath)
	if err != nil || strings.HasPrefix(rel, "..") {
		return localPath
	}
	return filepath.Join(hostRoot, rel)
}
func Hash(m artifacts.Manifest) string { b, _ := json.Marshal(m); return SHA(b) }
func SHA(b []byte) string              { sum := sha256.Sum256(b); return hex.EncodeToString(sum[:]) }
type syncCacheEntry struct {
	inputsMod int64
	syncedAt  time.Time
}

type scriptSnapCacheEntry struct {
	sig     string
	scripts []Script
}

var (
	syncedTaskCache sync.Map // key: root|taskID -> syncCacheEntry
	scriptSnapCache sync.Map // key: workDir -> scriptSnapCacheEntry
)

func (s *Service) taskInputsModTime(id int64) int64 {
	if s == nil || s.Root == "" || id <= 0 {
		return 0
	}
	p := filepath.Join(s.Root, "tasks", strconv.FormatInt(id, 10), "inputs")
	if info, err := os.Stat(p); err == nil {
		return info.ModTime().UnixNano()
	}
	return 0
}

func (s *Service) ensureSynced(ctx context.Context, id int64) error {
	if s == nil || id <= 0 {
		return nil
	}
	cacheKey := s.Root + "|" + strconv.FormatInt(id, 10)
	mod := s.taskInputsModTime(id)
	if v, ok := syncedTaskCache.Load(cacheKey); ok {
		entry := v.(syncCacheEntry)
		if entry.inputsMod == mod && time.Since(entry.syncedAt) < 2*time.Minute {
			return nil
		}
	}
	return s.Sync(ctx, id)
}

func (s *Service) Sync(ctx context.Context, id int64) error {
	m, err := (artifacts.Store{Root: s.Root}).Inputs(id, 0)
	if err != nil {
		return err
	}
	if mode, _, err := s.DB.TaskChallengeType(ctx, id); err == nil && strings.EqualFold(strings.TrimSpace(mode), "ad") {
		_, _ = s.RunPrecheck(ctx, id, false)
		syncedTaskCache.Store(s.Root+"|"+strconv.FormatInt(id, 10), syncCacheEntry{inputsMod: s.taskInputsModTime(id), syncedAt: time.Now()})
		return nil
	}
	if err := s.DB.SyncCTFInput(ctx, id, Hash(m)); err != nil {
		return err
	}
	_, _ = s.RunPrecheck(ctx, id, false)
	syncedTaskCache.Store(s.Root+"|"+strconv.FormatInt(id, 10), syncCacheEntry{inputsMod: s.taskInputsModTime(id), syncedAt: time.Now()})
	return nil
}
func (s *Service) WorkDir(task, intent int64) string {
	return filepath.Join(s.Root, "tasks", strconv.FormatInt(task, 10), fmt.Sprintf("i%d", intent), "ctf-work")
}
func (s *Service) SharedWorkDir(task int64) string {
	return filepath.Join(s.Root, "tasks", strconv.FormatInt(task, 10), "shared", "ctf-work")
}
func (s *Service) EffectiveSessionIntent(ctx context.Context, task, intent int64) int64 {
	sessionIntent, _, _, _ := s.resolveScope(ctx, task, intent)
	return sessionIntent
}
func (s *Service) EffectiveWorkDir(ctx context.Context, task, intent int64) string {
	_, workDir, _, _ := s.resolveScope(ctx, task, intent)
	return workDir
}
func (s *Service) LogicalPath(a artifacts.Artifact) string {
	return "/work/.inputs/" + a.ID + "/original"
}

func (s *Service) baselinePlaceholderFlags(ctx context.Context, taskID int64) []string {
	if s == nil || s.DB == nil || taskID <= 0 {
		return nil
	}
	raw, err := s.DB.TaskPrecheck(ctx, taskID)
	if err != nil || len(raw) == 0 {
		return nil
	}
	var pre PrecheckResult
	if json.Unmarshal(raw, &pre) != nil {
		return nil
	}
	return pre.BaselinePlaceholderFlags
}

// WorkArtifactEntry summarizes one reusable workspace file for cross-intent handoff.
type WorkArtifactEntry struct {
	Path    string
	Size    int64
	ModTime time.Time
}

// RecentWorkArtifacts lists up to limit most recently modified files in the task's
// effective /work directory (falling back to the latest sibling intent directory when
// a non-shared intent has not yet been seeded on disk).
func (s *Service) RecentWorkArtifacts(ctx context.Context, task, intent int64, limit int) []WorkArtifactEntry {
	if s == nil || s.Root == "" || task <= 0 {
		return nil
	}
	if limit <= 0 || limit > 32 {
		limit = 12
	}
	_, workDir, _, shared := s.resolveScope(ctx, task, intent)
	scanDir := workDir
	if !shared {
		if entries, err := os.ReadDir(scanDir); err != nil || len(entries) == 0 {
			// Fall back to the most recently modified sibling intent's ctf-work,
			// matching what seedNonSharedWorkDir will copy upon first execution.
			taskRoot := filepath.Join(s.Root, "tasks", strconv.FormatInt(task, 10))
			if dirEntries, derr := os.ReadDir(taskRoot); derr == nil {
				var bestDir string
				var bestMod time.Time
				for _, de := range dirEntries {
					if !de.IsDir() || !strings.HasPrefix(de.Name(), "i") {
						continue
					}
					cand := filepath.Join(taskRoot, de.Name(), "ctf-work")
					if cand == workDir {
						continue
					}
					if fi, serr := os.Stat(cand); serr == nil && fi.IsDir() {
						if sub, rerr := os.ReadDir(cand); rerr == nil && len(sub) > 0 && fi.ModTime().After(bestMod) {
							bestMod = fi.ModTime()
							bestDir = cand
						}
					}
				}
				if bestDir != "" {
					scanDir = bestDir
				}
			}
		}
	}
	if _, err := os.Stat(scanDir); err != nil {
		return nil
	}
	var out []WorkArtifactEntry
	_ = filepath.WalkDir(scanDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || p == scanDir {
			return nil
		}
		rel, rerr := filepath.Rel(scanDir, p)
		if rerr != nil {
			return nil
		}
		slash := filepath.ToSlash(rel)
		base := strings.ToLower(d.Name())
		if d.IsDir() {
			switch base {
			case ".inputs", ".cache", ".config", ".ghidra", ".jobs", ".interactive", ".snapshots", ".tools", "__pycache__", ".git", "node_modules":
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 || strings.HasSuffix(base, ".pyc") || strings.HasSuffix(base, ".tmp") || strings.HasSuffix(base, ".swp") {
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil || !info.Mode().IsRegular() {
			return nil
		}
		out = append(out, WorkArtifactEntry{
			Path:    "/work/" + slash,
			Size:    info.Size(),
			ModTime: info.ModTime(),
		})
		return nil
	})
	sort.Slice(out, func(i, j int) bool {
		if !out[i].ModTime.Equal(out[j].ModTime) {
			return out[i].ModTime.After(out[j].ModTime)
		}
		return out[i].Path < out[j].Path
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

func (s *Service) resolveScope(ctx context.Context, task, intent int64) (sessionIntent int64, workDir, lockKey string, shared bool) {
	if s != nil && s.DB != nil && task > 0 {
		if mode, challenge, err := s.DB.TaskChallengeType(ctx, task); err == nil && db.IsSandboxTaskMode(mode) {
			effective := strings.ToLower(strings.TrimSpace(challenge))
			if effective == "" || effective == "auto" {
				if preRaw, perr := s.DB.TaskPrecheck(ctx, task); perr == nil && len(preRaw) > 0 {
					var pre PrecheckResult
					if json.Unmarshal(preRaw, &pre) == nil && strings.TrimSpace(pre.InferredCategory) != "" {
						effective = strings.ToLower(strings.TrimSpace(pre.InferredCategory))
					}
				}
			}
			if effective == "pwn" || effective == "reverse" {
				return 0, s.SharedWorkDir(task), fmt.Sprintf("%s/%d/shared", s.Root, task), true
			}
		}
	}
	return intent, s.WorkDir(task, intent), fmt.Sprintf("%s/%d/%d", s.Root, task, intent), false
}

var executionLocks sync.Map

func executionLock(key string) func() {
	v, _ := executionLocks.LoadOrStore(key, &sync.Mutex{})
	m := v.(*sync.Mutex)
	m.Lock()
	return m.Unlock
}

func (s *Service) sessionKey(ctx context.Context, task, intent int64) (string, string, error) {
	sessionIntent, work, _, _ := s.resolveScope(ctx, task, intent)
	m, err := (artifacts.Store{Root: s.Root}).Inputs(task, sessionIntent)
	if err != nil {
		return "", "", err
	}
	spec := ctfrunner.SessionSpec{TaskID: task, IntentID: sessionIntent, InputHash: Hash(m)}
	return spec.Key(), work, nil
}

func (s *Service) prepareSession(ctx context.Context, task, intent int64) (string, ctfrunner.Session, artifacts.Manifest, string, error) {
	sessionIntent, work, _, _ := s.resolveScope(ctx, task, intent)
	store := artifacts.Store{Root: s.Root}
	m, err := store.Inputs(task, sessionIntent)
	if err != nil {
		return "", ctfrunner.Session{}, m, "", err
	}
	// Seed newly-created work directories for BOTH shared (pwn/reverse retries) and
	// non-shared scopes so retry rounds inherit ancestor /work scripts and artifacts.
	seedNonSharedWorkDir(s.Root, task, work, s.ancestorTaskIDs(task)...)
	if err = os.MkdirAll(work, 0700); err != nil {
		return "", ctfrunner.Session{}, m, "", err
	}
	spec, err := s.sessionSpec(ctx, task, sessionIntent, m, work)
	if err != nil {
		return "", ctfrunner.Session{}, m, "", err
	}
	if spec.VPNHash != "" {
		if vpnCfg, _, _, vpnErr := s.DB.TaskCTFVPN(ctx, task); vpnErr != nil {
			return "", ctfrunner.Session{}, m, "", fmt.Errorf("读取 CTF VPN 配置失败：%w", vpnErr)
		} else if _, err = s.Runner.SyncTaskVPN(ctx, task, spec.VPNHash, vpnCfg); err != nil {
			return "", ctfrunner.Session{}, m, "", fmt.Errorf("同步 CTF VPN 失败：%w", err)
		}
	}
	session, err := s.Runner.Prepare(ctx, spec)
	if err != nil {
		return "", session, m, "", err
	}
	key := spec.Key()
	if !session.InputsReady {
		if err = s.uploadInputs(ctx, key, task, m); err != nil {
			return "", session, m, "", err
		}
	}
	if !s.bindMountEnabled() && !session.WorkSeeded {
		if err = s.uploadWork(ctx, key, work); err != nil {
			return "", session, m, "", err
		}
	}
	return key, session, m, work, nil
}

func pendingCTFWaitError(pending *db.CTFCandidate) error {
	if pending.Kind == db.CTFCandidateExploitProof {
		return fmt.Errorf("已有漏洞利用证明等待用户在平台验证（候选 #%d）；自动探测已停止，请等待用户在赛题平台验证并确认结果", pending.ID)
	}
	return fmt.Errorf("已有候选 Flag 等待用户提交验证（候选 #%d）；自动探测已停止，请先在答案与验证中确认或否定", pending.ID)
}

func (s *Service) Execute(ctx context.Context, task, intent int64, command string, timeout int) (*db.CTFExecution, error) {
	return s.execute(ctx, task, intent, command, timeout, true, true)
}

// ExecuteRaw runs a sandbox command for deterministic automation (e.g. AD Repeater / Red-Blue Patcher)
// without stopping on pending Jeopardy candidates or creating spurious Jeopardy candidate rows.
func (s *Service) ExecuteRaw(ctx context.Context, task, intent int64, command string, timeout int) (*db.CTFExecution, error) {
	return s.execute(ctx, task, intent, command, timeout, false, false)
}

func (s *Service) execute(ctx context.Context, task, intent int64, command string, timeout int, enforcePendingCheck, autoCandidates bool) (*db.CTFExecution, error) {
	sessionIntent, _, lockKey, _ := s.resolveScope(ctx, task, intent)
	unlock := executionLock(lockKey)
	defer unlock()
	if err := s.ensureSynced(ctx, task); err != nil {
		return nil, err
	}
	if enforcePendingCheck {
		if pending, err := s.DB.PendingCTFSubmission(ctx, task); err != nil {
			return nil, err
		} else if pending != nil {
			return nil, pendingCTFWaitError(pending)
		}
	}
	key, session, m, work, err := s.prepareSession(ctx, task, intent)
	if err != nil {
		return nil, err
	}
	store := artifacts.Store{Root: s.Root}
	// Legacy prompts and resumed conversations may still carry application paths.
	for _, a := range m.Files {
		p, e := store.InputPath(task, a)
		if e != nil {
			return nil, e
		}
		command = strings.ReplaceAll(command, p, s.LogicalPath(a))
	}
	command = strings.ReplaceAll(command, work, "/work")
	if legacy := s.WorkDir(task, intent); legacy != work {
		command = strings.ReplaceAll(command, legacy, "/work")
	}
	spec := ctfrunner.SessionSpec{TaskID: task, IntentID: sessionIntent, InputHash: Hash(m)}
	e := &db.CTFExecution{ID: uuid.NewString(), TaskID: task, IntentID: intent, InputHash: spec.InputHash, Command: command, ExitCode: -1, StartedAt: time.Now().UTC()}
	e.Environment, _ = json.Marshal(map[string]any{"image": session.Image, "image_id": session.ImageID})
	result, runErr := s.Runner.Execute(ctx, key, command, timeout)
	if !result.StartedAt.IsZero() {
		e.StartedAt = result.StartedAt
	}
	end := result.FinishedAt
	if end.IsZero() {
		end = time.Now().UTC()
	}
	e.FinishedAt = &end
	e.ExitCode = result.ExitCode
	e.Truncated = result.Truncated
	e.Error = result.Error
	if runErr != nil {
		e.Error = runErr.Error()
	}
	// Persist a cancelled execution too. The runner kills its container on timeout.
	saveCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	if runErr == nil && result.Error == "" && !s.bindMountEnabled() {
		if body, er := s.Runner.Download(saveCtx, key); er == nil {
			er = s.extractWork(body, work)
			body.Close()
			if er != nil {
				e.Error = "工作文件同步失败：" + er.Error()
			}
		} else {
			e.Error = "工作文件同步失败：" + er.Error()
		}
	}
	dir := filepath.Join(s.Root, "tasks", fmt.Sprint(task), "ctf", "executions", e.ID)
	if err = os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	e.StdoutPath = filepath.ToSlash(filepath.Join("ctf", "executions", e.ID, "stdout.log"))
	e.StderrPath = filepath.ToSlash(filepath.Join("ctf", "executions", e.ID, "stderr.log"))
	if err = os.WriteFile(filepath.Join(dir, "stdout.log"), result.Stdout, 0600); err != nil {
		return nil, err
	}
	if err = os.WriteFile(filepath.Join(dir, "stderr.log"), result.Stderr, 0600); err != nil {
		return nil, err
	}
	e.StdoutSHA = SHA(result.Stdout)
	e.StderrSHA = SHA(result.Stderr)
	e.StdoutExcerpt = excerpt(result.Stdout, 16000)
	e.StderrExcerpt = excerpt(result.Stderr, 8000)
	files, err := s.snapshotScriptsCached(task, work, dir)
	if err != nil {
		return nil, err
	}
	e.Files, _ = json.Marshal(files)
	if err = s.DB.SaveCTFExecution(saveCtx, e); err != nil {
		return nil, err
	}
	if autoCandidates {
		if verifyMode, _ := s.DB.TaskCTFVerifyMode(saveCtx, task); verifyMode != db.CTFVerifyExploitProof {
			baselines := s.baselinePlaceholderFlags(saveCtx, task)
			var verdicts []string
			for _, flag := range ExtractFlags(string(result.Stdout)+"\n"+string(result.Stderr), 32) {
				if IsSelfConstructedMockFlag(command, flag) || IsBaselinePlaceholderFlag(baselines, flag) {
					continue
				}
				if cid, addErr := s.DB.AddCTFOutputCandidate(saveCtx, task, e.ID, flag); addErr != nil {
					return nil, addErr
				} else if cid > 0 && BenchmarkFlagHook != nil {
					if v, handled, _ := BenchmarkFlagHook(saveCtx, task, e.ID, flag, ""); handled && v != "" {
						verdicts = append(verdicts, v)
					}
				}
			}
			if len(verdicts) > 0 {
				e.StdoutExcerpt = strings.TrimRight(e.StdoutExcerpt, "\n") + "\n[测评平台自动验真回执] " + strings.Join(verdicts, " | ")
			}
		}
	}
	return e, nil
}

func (s *Service) StartJob(ctx context.Context, task, intent int64, command, jobID string) (*ctfrunner.JobInfo, error) {
	sessionIntent, _, lockKey, _ := s.resolveScope(ctx, task, intent)
	unlock := executionLock(lockKey)
	defer unlock()
	if err := s.ensureSynced(ctx, task); err != nil {
		return nil, err
	}
	if pending, err := s.DB.PendingCTFSubmission(ctx, task); err != nil {
		return nil, err
	} else if pending != nil {
		return nil, pendingCTFWaitError(pending)
	}
	key, session, m, work, err := s.prepareSession(ctx, task, intent)
	if err != nil {
		return nil, err
	}
	store := artifacts.Store{Root: s.Root}
	for _, a := range m.Files {
		if p, e := store.InputPath(task, a); e == nil {
			command = strings.ReplaceAll(command, p, s.LogicalPath(a))
		}
	}
	command = strings.ReplaceAll(command, work, "/work")
	if legacy := s.WorkDir(task, intent); legacy != work {
		command = strings.ReplaceAll(command, legacy, "/work")
	}

	execID := uuid.NewString()
	spec := ctfrunner.SessionSpec{TaskID: task, IntentID: sessionIntent, InputHash: Hash(m)}
	e := &db.CTFExecution{
		ID:        execID,
		TaskID:    task,
		IntentID:  intent,
		InputHash: spec.InputHash,
		Command:   "[bg: " + jobID + "] " + command,
		ExitCode:  -1,
		StartedAt: time.Now().UTC(),
	}
	e.Environment, _ = json.Marshal(map[string]any{"image": session.Image, "image_id": session.ImageID})
	if err = s.DB.SaveCTFExecution(ctx, e); err != nil {
		return nil, err
	}

	info, err := s.Runner.StartJob(ctx, key, command, jobID, execID)
	if err != nil {
		return nil, err
	}
	info.ExecID = execID
	return info, nil
}

func (s *Service) ListJobs(ctx context.Context, task, intent int64) ([]ctfrunner.JobInfo, error) {
	key, _, err := s.sessionKey(ctx, task, intent)
	if err != nil {
		return nil, err
	}
	return s.Runner.ListJobs(ctx, key)
}

func (s *Service) JobStatus(ctx context.Context, task, intent int64, jobID string, tailLines int) (*ctfrunner.JobStatus, error) {
	key, _, err := s.sessionKey(ctx, task, intent)
	if err != nil {
		return nil, err
	}
	status, err := s.Runner.JobStatus(ctx, key, jobID, tailLines)
	if err != nil {
		return nil, err
	}
	if verifyMode, _ := s.DB.TaskCTFVerifyMode(ctx, task); verifyMode != db.CTFVerifyExploitProof {
		combined := status.Stdout + "\n" + status.Stderr
		var verdicts []string
		for _, flag := range ExtractFlags(combined, 16) {
			execID := status.ExecID
			if execID == "" {
				execID = status.ID
			}
			if cid, addErr := s.DB.AddCTFOutputCandidate(ctx, task, execID, flag); addErr == nil && cid > 0 && BenchmarkFlagHook != nil {
				if v, handled, _ := BenchmarkFlagHook(ctx, task, execID, flag, ""); handled && v != "" {
					verdicts = append(verdicts, v)
				}
			}
		}
		if len(verdicts) > 0 {
			status.Stdout = strings.TrimRight(status.Stdout, "\n") + "\n[测评平台自动验真回执] " + strings.Join(verdicts, " | ")
		}
	}
	return status, nil
}

func (s *Service) StopJob(ctx context.Context, task, intent int64, jobID string) error {
	key, _, err := s.sessionKey(ctx, task, intent)
	if err != nil {
		return err
	}
	return s.Runner.StopJob(ctx, key, jobID)
}

func (s *Service) StartInteractive(ctx context.Context, task, intent int64, command, sid string) (*ctfrunner.InteractiveSessionInfo, error) {
	key, session, _, _, err := s.prepareSession(ctx, task, intent)
	if err != nil {
		return nil, err
	}
	execID := uuid.NewString()
	e := &db.CTFExecution{
		ID:        execID,
		TaskID:    task,
		IntentID:  intent,
		InputHash: session.Spec.InputHash,
		Command:   "[interactive] " + command,
		ExitCode:  -1,
		StartedAt: time.Now().UTC(),
	}
	e.Environment, _ = json.Marshal(map[string]any{"image": session.Image, "image_id": session.ImageID, "interactive_sid": sid})
	if err = s.DB.SaveCTFExecution(ctx, e); err != nil {
		return nil, err
	}

	info, err := s.Runner.StartInteractive(ctx, key, command, sid, execID)
	if err != nil {
		return nil, err
	}
	info.ExecID = execID
	return info, nil
}

func (s *Service) ListInteractive(ctx context.Context, task, intent int64) ([]ctfrunner.InteractiveSessionInfo, error) {
	key, _, err := s.sessionKey(ctx, task, intent)
	if err != nil {
		return nil, err
	}
	return s.Runner.ListInteractive(ctx, key)
}

func (s *Service) WriteInteractive(ctx context.Context, task, intent int64, sid, data, encoding string, autoNewline bool) (*ctfrunner.InteractiveWriteResult, error) {
	key, _, err := s.sessionKey(ctx, task, intent)
	if err != nil {
		return nil, err
	}
	return s.Runner.WriteInteractive(ctx, key, sid, data, encoding, autoNewline)
}

func (s *Service) ReadInteractive(ctx context.Context, task, intent int64, sid string, offset int64, waitMs int) (*ctfrunner.InteractiveReadResult, error) {
	key, _, err := s.sessionKey(ctx, task, intent)
	if err != nil {
		return nil, err
	}
	res, err := s.Runner.ReadInteractive(ctx, key, sid, offset, waitMs)
	if err != nil {
		return nil, err
	}
	if res.Output != "" {
		if verifyMode, _ := s.DB.TaskCTFVerifyMode(ctx, task); verifyMode != db.CTFVerifyExploitProof {
			execID := res.ExecID
			if execID == "" {
				execID = sid
			}
			var verdicts []string
			for _, flag := range ExtractFlags(res.Output, 16) {
				if cid, addErr := s.DB.AddCTFOutputCandidate(ctx, task, execID, flag); addErr == nil && cid > 0 && BenchmarkFlagHook != nil {
					if v, handled, _ := BenchmarkFlagHook(ctx, task, execID, flag, ""); handled && v != "" {
						verdicts = append(verdicts, v)
					}
				}
			}
			if len(verdicts) > 0 {
				res.Output = strings.TrimRight(res.Output, "\n") + "\n[测评平台自动验真回执] " + strings.Join(verdicts, " | ")
			}
		}
	}
	return res, nil
}

func (s *Service) CloseInteractive(ctx context.Context, task, intent int64, sid string) error {
	key, _, err := s.sessionKey(ctx, task, intent)
	if err != nil {
		return err
	}
	return s.Runner.CloseInteractive(ctx, key, sid)
}

// CreateSavepoint freezes the container /work state via hardlink snapshot.
func (s *Service) CreateSavepoint(ctx context.Context, task, intent int64, id string) (ctfrunner.SavepointResult, error) {
	_, _, lockKey, _ := s.resolveScope(ctx, task, intent)
	unlock := executionLock(lockKey)
	defer unlock()
	key, _, _, _, err := s.prepareSession(ctx, task, intent)
	if err != nil {
		return ctfrunner.SavepointResult{}, err
	}
	return s.Runner.CreateSavepoint(ctx, key, id)
}

// Rewind restores a previously created /work savepoint and syncs back to host mirror when needed.
func (s *Service) Rewind(ctx context.Context, task, intent int64, id string) (ctfrunner.RewindResult, error) {
	_, _, lockKey, _ := s.resolveScope(ctx, task, intent)
	unlock := executionLock(lockKey)
	defer unlock()
	key, work, err := s.sessionKey(ctx, task, intent)
	if err != nil {
		return ctfrunner.RewindResult{}, err
	}
	res, err := s.Runner.Rewind(ctx, key, id)
	if err != nil {
		return res, err
	}
	if !s.bindMountEnabled() {
		if body, dlErr := s.Runner.Download(ctx, key); dlErr == nil {
			syncErr := s.extractWork(body, work)
			body.Close()
			if syncErr != nil {
				return res, fmt.Errorf("读档后工作文件同步失败：%w", syncErr)
			}
		} else {
			return res, fmt.Errorf("读档后工作文件同步失败：%w", dlErr)
		}
	}
	return res, nil
}

func excerpt(b []byte, n int) string {
	suffix := ""
	if len(b) > n {
		b = b[:n]
		suffix = "\n[输出节选；完整日志可下载]"
	}
	return strings.ToValidUTF8(strings.ReplaceAll(string(b), "\x00", ""), "�") + suffix
}

// seedNonSharedWorkDir 在非共享模式下（如 Web/Misc/Crypto），当新意图的 ctf-work 尚未创建时，
// 按“前序重跑任务（ancestorTasks，由旧到新）→ 当前任务已有 i*/ctf-work（按修改时间由旧到新）”顺序
// 合并持久产物与具名脚本（如 exp2.py、check_rce.py、凭据与跳板脚本），避免后续意图或重试轮次丢失前序成果；
// 同时仅跳过默认临时草稿 solve.py / debug.gdb 与编译缓存文件。
func seedNonSharedWorkDir(root string, task int64, targetWork string, ancestorTasks ...int64) {
	if _, err := os.Stat(targetWork); err == nil {
		return
	}
	type seedDir struct {
		rank    int
		path    string
		name    string
		modTime time.Time
	}
	collectTaskDirs := func(taskID int64, rank int, includeShared bool) []seedDir {
		taskDir := filepath.Join(root, "tasks", strconv.FormatInt(taskID, 10))
		entries, err := os.ReadDir(taskDir)
		if err != nil {
			return nil
		}
		var dirs []seedDir
		for _, ent := range entries {
			if !ent.IsDir() {
				continue
			}
			name := ent.Name()
			if !strings.HasPrefix(name, "i") && (!includeShared || name != "shared") {
				continue
			}
			cand := filepath.Join(taskDir, name, "ctf-work")
			if cand == targetWork {
				continue
			}
			if sub, err := os.ReadDir(cand); err == nil && len(sub) > 0 {
				var mt time.Time
				if info, ierr := os.Stat(cand); ierr == nil {
					mt = info.ModTime()
				}
				dirs = append(dirs, seedDir{rank: rank, path: cand, name: name, modTime: mt})
			}
		}
		return dirs
	}
	var srcDirs []seedDir
	for idx, anc := range ancestorTasks {
		if anc > 0 && anc != task {
			srcDirs = append(srcDirs, collectTaskDirs(anc, idx, true)...)
		}
	}
	srcDirs = append(srcDirs, collectTaskDirs(task, len(ancestorTasks)+1, false)...)
	if len(srcDirs) == 0 {
		return
	}
	sort.Slice(srcDirs, func(i, j int) bool {
		if srcDirs[i].rank != srcDirs[j].rank {
			return srcDirs[i].rank < srcDirs[j].rank
		}
		if !srcDirs[i].modTime.Equal(srcDirs[j].modTime) {
			return srcDirs[i].modTime.Before(srcDirs[j].modTime)
		}
		return srcDirs[i].name < srcDirs[j].name
	})
	const maxSeedBytes int64 = 64 << 20
	const maxSeedFiles = 256
	var copiedBytes int64
	copiedFiles := 0
	for _, sd := range srcDirs {
		srcDir := sd.path
		_ = filepath.WalkDir(srcDir, func(p string, d fs.DirEntry, err error) error {
			if err != nil || p == srcDir {
				return err
			}
			rel, e := filepath.Rel(srcDir, p)
			if e != nil {
				return nil
			}
			slash := filepath.ToSlash(rel)
			base := strings.ToLower(d.Name())
			if base == ".cache" || base == ".config" || base == ".tools" || base == "__pycache__" || strings.HasPrefix(slash, ".inputs") {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if d.Type()&os.ModeSymlink != 0 {
				return nil
			}
			dst := filepath.Join(targetWork, rel)
			if d.IsDir() {
				return os.MkdirAll(dst, 0700)
			}
			if base == "solve.py" || base == "debug.gdb" || strings.HasSuffix(base, ".pyc") || strings.HasSuffix(base, ".tmp") || strings.HasSuffix(base, ".swp") {
				return nil
			}
			info, e := d.Info()
			if e != nil || !info.Mode().IsRegular() {
				return nil
			}
			if info.Size() > 32<<20 || copiedBytes+info.Size() > maxSeedBytes || copiedFiles+1 > maxSeedFiles {
				return nil
			}
			if err := os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
				return nil
			}
			data, e := os.ReadFile(p)
			if e != nil {
				return nil
			}
			mode := os.FileMode(0600)
			if info.Mode()&0111 != 0 {
				mode = 0700
			}
			if err := os.WriteFile(dst, data, mode); err == nil {
				copiedBytes += info.Size()
				copiedFiles++
			}
			return nil
		})
	}
}

func streamTar(ctx context.Context, send func(io.Reader) error, build func(*tar.Writer) error) error {
	pr, pw := io.Pipe()
	done := make(chan error, 1)
	go func() {
		tw := tar.NewWriter(pw)
		err := build(tw)
		if err == nil {
			err = tw.Close()
		}
		pw.CloseWithError(err)
		done <- err
	}()
	err := send(pr)
	pr.CloseWithError(err)
	buildErr := <-done
	if err != nil {
		return err
	}
	return buildErr
}
func (s *Service) uploadInputs(ctx context.Context, key string, task int64, m artifacts.Manifest) error {
	return streamTar(ctx, func(r io.Reader) error { return s.Runner.Upload(ctx, key, true, r) }, func(tw *tar.Writer) error {
		if err := tw.WriteHeader(&tar.Header{Name: ".inputs/", Typeflag: tar.TypeDir, Mode: 0555}); err != nil {
			return err
		}
		entries := []map[string]any{}
		for _, a := range m.Files {
			entries = append(entries, map[string]any{"id": a.ID, "name": a.Name, "path": s.LogicalPath(a), "sha256": a.SHA256, "role": a.Role, "size": a.Size, "analysis": a.Analysis})
		}
		manifest, _ := json.MarshalIndent(entries, "", "  ")
		if err := tw.WriteHeader(&tar.Header{Name: ".inputs/manifest.json", Typeflag: tar.TypeReg, Mode: 0444, Size: int64(len(manifest))}); err != nil {
			return err
		}
		if _, err := tw.Write(manifest); err != nil {
			return err
		}
		store := artifacts.Store{Root: s.Root}
		for _, a := range m.Files {
			p := ".inputs/" + a.ID + "/"
			if err := tw.WriteHeader(&tar.Header{Name: p, Typeflag: tar.TypeDir, Mode: 0555}); err != nil {
				return err
			}
			f, _, err := store.Open("task", fmt.Sprint(task), a.ID)
			if err != nil {
				return err
			}
			err = tw.WriteHeader(&tar.Header{Name: p + "original", Size: a.Size, Typeflag: tar.TypeReg, Mode: 0444})
			if err == nil {
				_, err = io.CopyN(tw, f, a.Size)
			}
			f.Close()
			if err != nil {
				return err
			}
		}
		return nil
	})
}
const (
	defaultMaxWorkMB       = 512
	maxWorkFiles           = 8192
	maxSingleSyncFileBytes = 64 << 20
)

func maxWorkBytes() int64 {
	if raw := strings.TrimSpace(os.Getenv("P3Y_BOX_WORKDIR_MAX_MB")); raw != "" {
		if mb, err := strconv.Atoi(raw); err == nil && mb >= 64 {
			if mb > 2048 {
				mb = 2048
			}
			return int64(mb) << 20
		}
	}
	return defaultMaxWorkMB << 20
}

func (s *Service) uploadWork(ctx context.Context, key, dir string) error {
	limit := maxWorkBytes()
	return streamTar(ctx, func(r io.Reader) error { return s.Runner.Upload(ctx, key, false, r) }, func(tw *tar.Writer) error {
		var total int64
		count := 0
		return filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if p == dir {
				return nil
			}
			rel, _ := filepath.Rel(dir, p)
			name := filepath.ToSlash(rel)
			if d.Type()&os.ModeSymlink != 0 {
				return errors.New("工作目录不允许符号链接")
			}
			if strings.HasPrefix(name, ".inputs") {
				return errors.New("受保护的输入路径")
			}
			info, err := d.Info()
			if err != nil {
				return err
			}
			if !info.IsDir() && !info.Mode().IsRegular() {
				return errors.New("工作目录不允许特殊文件")
			}
			// Skip oversized intermediate files on host cache rather than deadlocking container commands.
			if !info.IsDir() && (info.Size() > maxSingleSyncFileBytes || total+info.Size() > limit || count+1 > maxWorkFiles) {
				return nil
			}
			if info.IsDir() && count+1 > maxWorkFiles {
				return nil
			}
			total += info.Size()
			count++
			h, err := tar.FileInfoHeader(info, "")
			if err != nil {
				return err
			}
			h.Name = name
			if err = tw.WriteHeader(h); err != nil {
				return err
			}
			if !info.IsDir() {
				f, err := os.Open(p)
				if err != nil {
					return err
				}
				_, err = io.CopyN(tw, f, info.Size())
				f.Close()
				return err
			}
			return nil
		})
	})
}
func safeWorkPath(root, name string) (string, error) {
	if name == "" || strings.ContainsAny(name, "\\:\x00") || path.IsAbs(name) || path.Clean(name) != strings.TrimSuffix(name, "/") || name == ".." || strings.HasPrefix(name, "../") || strings.HasPrefix(name, ".inputs") {
		return "", errors.New("非法工作文件路径")
	}
	p := filepath.Join(root, filepath.FromSlash(name))
	for cur := p; cur != root; cur = filepath.Dir(cur) {
		info, err := os.Lstat(cur)
		if err == nil && info.Mode()&os.ModeSymlink != 0 {
			return "", errors.New("拒绝符号链接路径")
		}
		if err != nil && !os.IsNotExist(err) {
			return "", err
		}
		if filepath.Dir(cur) == cur {
			return "", errors.New("路径超出任务目录")
		}
	}
	return p, nil
}
func (s *Service) extractWork(r io.Reader, dir string) error {
	limit := maxWorkBytes()
	stage := dir + ".sync-" + uuid.NewString()
	if err := os.MkdirAll(stage, 0700); err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(stage) }()

	tr := tar.NewReader(io.LimitReader(r, limit+(16<<20)))
	var total int64
	count := 0
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return syncStageToDir(stage, dir)
		}
		if err != nil {
			return err
		}
		p, err := safeWorkPath(stage, h.Name)
		if err != nil {
			return err
		}
		total += h.Size
		count++
		if h.Size < 0 || total > limit || count > maxWorkFiles {
			return errors.New("工作文件同步超过限制")
		}
		if h.Typeflag == tar.TypeDir {
			if err = os.MkdirAll(p, 0700); err != nil {
				return err
			}
			continue
		}
		if h.Typeflag != tar.TypeReg {
			return errors.New("拒绝工作文件链接或设备")
		}
		if err = os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			return err
		}
		mode := os.FileMode(0600)
		if h.Mode&0111 != 0 {
			mode = 0700
		}
		f, err := os.OpenFile(p, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
		if err != nil {
			return err
		}
		_, err = io.CopyN(f, tr, h.Size)
		ce := f.Close()
		if err != nil {
			return err
		}
		if ce != nil {
			return ce
		}
	}
}

func syncStageToDir(stage, dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	keep := map[string]bool{}
	err := filepath.WalkDir(stage, func(p string, d fs.DirEntry, err error) error {
		if err != nil || p == stage {
			return err
		}
		rel, e := filepath.Rel(stage, p)
		if e != nil {
			return e
		}
		keep[filepath.ToSlash(rel)] = true
		return nil
	})
	if err != nil {
		return err
	}
	var stale []string
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || p == dir {
			return nil
		}
		rel, e := filepath.Rel(dir, p)
		if e == nil && !keep[filepath.ToSlash(rel)] {
			stale = append(stale, p)
		}
		return nil
	})
	for i := len(stale) - 1; i >= 0; i-- {
		_ = os.RemoveAll(stale[i])
	}
	return filepath.WalkDir(stage, func(p string, d fs.DirEntry, err error) error {
		if err != nil || p == stage {
			return err
		}
		rel, e := filepath.Rel(stage, p)
		if e != nil {
			return e
		}
		dst := filepath.Join(dir, rel)
		if d.IsDir() {
			return os.MkdirAll(dst, 0700)
		}
		if err = os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
			return err
		}
		_ = os.Remove(dst)
		return os.Rename(p, dst)
	})
}

type Script struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

func snapshotScriptsSignature(work string) (string, error) {
	var parts []string
	err := filepath.WalkDir(work, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != work {
				switch strings.ToLower(d.Name()) {
				case ".inputs", ".cache", ".config", ".ghidra", ".jobs", ".interactive", ".snapshots", ".tools", "__pycache__", ".git", "node_modules":
					return filepath.SkipDir
				}
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(p))
		if ext != ".py" && ext != ".sh" && ext != ".gdb" && ext != ".c" && ext != ".js" && ext != ".txt" {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Size() > 128<<10 || len(parts) >= 32 {
			return nil
		}
		name, _ := filepath.Rel(work, p)
		parts = append(parts, fmt.Sprintf("%s|%d|%d", filepath.ToSlash(name), info.Size(), info.ModTime().UnixNano()))
		return nil
	})
	return strings.Join(parts, "\n"), err
}

func (s *Service) snapshotScriptsCached(task int64, work, dir string) ([]Script, error) {
	sig, err := snapshotScriptsSignature(work)
	if err != nil {
		return snapshotScripts(work, dir)
	}
	if v, ok := scriptSnapCache.Load(work); ok {
		entry := v.(scriptSnapCacheEntry)
		if entry.sig == sig {
			allExist := true
			taskRoot := filepath.Join(s.Root, "tasks", strconv.FormatInt(task, 10))
			for _, sc := range entry.scripts {
				if _, serr := os.Stat(filepath.Join(taskRoot, filepath.FromSlash(sc.Path))); serr != nil {
					allExist = false
					break
				}
			}
			if allExist {
				out := make([]Script, len(entry.scripts))
				copy(out, entry.scripts)
				return out, nil
			}
		}
	}
	out, err := snapshotScripts(work, dir)
	if err == nil {
		cached := make([]Script, len(out))
		copy(cached, out)
		scriptSnapCache.Store(work, scriptSnapCacheEntry{sig: sig, scripts: cached})
	}
	return out, err
}

func snapshotScripts(work, dir string) ([]Script, error) {
	out := []Script{}
	err := filepath.WalkDir(work, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != work {
				switch strings.ToLower(d.Name()) {
				case ".inputs", ".cache", ".config", ".ghidra", ".jobs", ".interactive", ".snapshots", ".tools", "__pycache__", ".git", "node_modules":
					return filepath.SkipDir
				}
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(p))
		if ext != ".py" && ext != ".sh" && ext != ".gdb" && ext != ".c" && ext != ".js" && ext != ".txt" {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Size() > 128<<10 || len(out) >= 32 {
			return nil
		}
		name, _ := filepath.Rel(work, p)
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		stored := fmt.Sprintf("script-%02d%s", len(out)+1, ext)
		if err = os.WriteFile(filepath.Join(dir, stored), b, 0600); err != nil {
			return err
		}
		out = append(out, Script{Name: filepath.ToSlash(name), Path: filepath.ToSlash(filepath.Join("ctf", "executions", filepath.Base(dir), stored)), SHA256: SHA(b), Size: int64(len(b))})
		return nil
	})
	return out, err
}
func (s *Service) EvidenceFile(task int64, name, hash string) ([]byte, error) {
	root := filepath.Join(s.Root, "tasks", fmt.Sprint(task))
	p, err := safeWorkPath(root, name)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 9<<20))
	if err != nil {
		return nil, err
	}
	if SHA(b) != hash {
		return nil, errors.New("执行证据摘要不匹配")
	}
	return b, nil
}
func (s *Service) Submit(ctx context.Context, task int64, exec, value string) (int64, error) {
	id, _, err := s.SubmitWithSubFlag(ctx, task, exec, value, "")
	return id, err
}

func (s *Service) SubmitWithSubFlag(ctx context.Context, task int64, exec, value, subFlagID string) (int64, string, error) {
	e, err := s.DB.CTFExecution(ctx, task, exec)
	if err != nil {
		return 0, "", err
	}
	out, err := s.EvidenceFile(task, e.StdoutPath, e.StdoutSHA)
	if err != nil {
		return 0, "", err
	}
	stderr, err := s.EvidenceFile(task, e.StderrPath, e.StderrSHA)
	if err != nil {
		return 0, "", err
	}
	if value == "" || (!bytes.Contains(out, []byte(value)) && !bytes.Contains(stderr, []byte(value))) {
		return 0, "", errors.New("候选答案必须出现在本任务该次执行的真实输出中")
	}
	id, err := s.DB.AddCTFCandidate(ctx, task, exec, value)
	if err != nil {
		return 0, "", err
	}
	var verdict string
	if BenchmarkFlagHook != nil {
		if v, handled, hookErr := BenchmarkFlagHook(ctx, task, exec, value, strings.TrimSpace(subFlagID)); hookErr != nil {
			return id, "", hookErr
		} else if handled {
			verdict = v
		}
	}
	return id, verdict, nil
}

// SubmitExploitProof records a non-flag exploit proof candidate backed by a real
// container execution for exploit_proof or flag_and_exploit CTF tasks.
func (s *Service) SubmitExploitProof(ctx context.Context, task int64, exec, proofSummary, targetEffect string) (int64, error) {
	verifyMode, err := s.DB.TaskCTFVerifyMode(ctx, task)
	if err != nil {
		return 0, err
	}
	if verifyMode != db.CTFVerifyExploitProof && verifyMode != db.CTFVerifyFlagAndExploit {
		return 0, errors.New("当前任务验收模式为「仅提交 Flag」，请使用 ctf_submit_flag 提交答案，或在详情页切换验收方式")
	}
	proofSummary = strings.TrimSpace(proofSummary)
	targetEffect = strings.TrimSpace(targetEffect)
	if proofSummary == "" {
		return 0, errors.New("proof_summary 不能为空")
	}
	e, err := s.DB.CTFExecution(ctx, task, exec)
	if err != nil {
		return 0, err
	}
	out, err := s.EvidenceFile(task, e.StdoutPath, e.StdoutSHA)
	if err != nil {
		return 0, err
	}
	stderr, err := s.EvidenceFile(task, e.StderrPath, e.StderrSHA)
	if err != nil {
		return 0, err
	}
	if strings.TrimSpace(string(out)) == "" && strings.TrimSpace(string(stderr)) == "" && len(e.Files) <= 2 {
		return 0, errors.New("漏洞利用证明必须基于有真实输出或脚本产物的执行记录")
	}
	return s.DB.AddCTFExploitProofCandidate(ctx, task, exec, proofSummary, targetEffect)
}
