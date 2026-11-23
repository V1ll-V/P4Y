package agent

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path"
	"path/filepath"
	"strings"
	"time"

	"p3y/ctf"
	"p3y/db"
	actool "github.com/Autumn-27/norma/tool"
)

type (
	ctfRunKey       struct{}
	ctfWebSkillsKey struct{}
	ctfProxyKey     struct{}
	ctfDeferredKey  struct{}
)

type ctfProxyVal struct {
	addr   string
	caCert string
}

type ctfDeferredVal struct {
	deferred []string
	unlock   *actool.UnlockSet
	packs    map[string][]string
	targets  *[]*actool.UnlockSet
}

// BenchmarkChoiceHook submits objective choice-question answers on zero-touch benchmark tasks.
var BenchmarkChoiceHook func(ctx context.Context, taskID int64, choices []string) (verdictJSON string, handled bool, err error)

// BenchmarkHintHook handles active Worker requests for a platform Hint on zero-touch benchmark tasks.
var BenchmarkHintHook func(ctx context.Context, taskID int64, reason string) (hintText string, handled bool, err error)

// BenchmarkExtraToolsHook injects platform-specific safe MCP tools for a benchmark task.
var BenchmarkExtraToolsHook func(ctx context.Context, taskID int64) []actool.CoreTool

// BenchmarkContextHook appends live benchmark context (targets, multi-flag slots, skills) to prompts.
var BenchmarkContextHook func(ctx context.Context, taskID int64, role string) string

// WithCTFProxy attaches optional MITM proxy coordinates so CTF container tools
// can route HTTP/HTTPS traffic through the host's recording proxy.
func WithCTFProxy(ctx context.Context, addr, caCert string) context.Context {
	addr = strings.TrimSpace(addr)
	caCert = strings.TrimSpace(caCert)
	if addr == "" && caCert == "" {
		return ctx
	}
	return context.WithValue(ctx, ctfProxyKey{}, ctfProxyVal{addr: addr, caCert: caCert})
}

func ctfProxyFromContext(ctx context.Context) (string, string) {
	if ctx == nil {
		return "", ""
	}
	v, _ := ctx.Value(ctfProxyKey{}).(ctfProxyVal)
	return v.addr, v.caCert
}

const (
	ctfPackAll        = "all"
	ctfPackBinary     = "binary"
	ctfPackWeb        = "web"
	ctfPackCryptoMisc = "crypto_misc"
)

func ctfToolPackForChallenge(challenge string) string {
	switch strings.ToLower(strings.TrimSpace(challenge)) {
	case "pwn", "reverse":
		return ctfPackBinary
	case "web":
		return ctfPackWeb
	case "crypto", "misc":
		return ctfPackCryptoMisc
	default:
		return ctfPackAll
	}
}

func ctfToolPackOf(name string) string {
	switch name {
	case "ctf_binary_info", "ctf_pwn_triage", "ctf_gdb", "ctf_decompile", "ctf_radare2", "diff_local_remote":
		return ctfPackBinary
	case "ctf_http", "http_fuzz_diff", "http_race_probe":
		return ctfPackWeb
	case "ctf_pcap_analyze":
		return ctfPackCryptoMisc
	default:
		return ""
	}
}

// CTF runs cannot acquire a second, application-host shell through MCP or the
// configurable shell_* catalog. Web CTF challenges may load safe skills
// (such as playwright-cli) while host shells remain strictly blocked.
func ctfBase(ctx context.Context, root string, ts *db.ExplorationStore, task, intent int64, base []actool.CoreTool) (context.Context, []actool.CoreTool) {
	if ts == nil {
		return ctx, base
	}
	mode, challenge, _, err := ts.TaskInputMetadata()
	if err != nil || !db.IsSandboxTaskMode(mode) {
		return ctx, base
	}
	service := ctf.New(root, ts.Database())
	if proxyAddr, proxyCA := ctfProxyFromContext(ctx); proxyAddr != "" {
		service.WithProxy(proxyAddr, proxyCA)
	}
	verifyMode := ""
	if mode == "ctf" {
		verifyMode, _ = ts.Database().TaskCTFVerifyMode(ctx, task)
	} else if mode == "ad" {
		// AD tasks use Attack-Defense workflows (Repeater/Catcher/Patcher + findings) rather than Jeopardy flag/proof confirmation.
		verifyMode = "ad_none"
	}
	out := []actool.CoreTool{}
	for _, t := range base {
		switch t.Name() {
		case "Bash", "Read", "Write", "Edit", "MultiEdit", "Glob", "Grep", "LS", "http_send":
			continue
		case "report_finding", "update_finding_report", "list_findings", "insert_assets", "list_assets":
			if mode == "ctf" {
				continue // CTF answers use their own evidence/WP flow, not enterprise asset/finding registries.
			}
		}
		out = append(out, t)
	}
	unlock := actool.NewUnlockSet()
	targets := []*actool.UnlockSet{unlock}
	built := ctfToolsWithUnlock(service, task, intent, verifyMode, &targets)
	activePack := ctfToolPackForChallenge(challenge)
	activePacks := map[string]bool{}
	if activePack != ctfPackAll {
		activePacks[activePack] = true
		// Zero-turn cross-domain auto-unlock: when Phase-0 Precheck detected
		// cross-domain artifacts or targets (e.g., an ELF inside a Web task,
		// an HTTP portal inside a Pwn task, or a PCAP inside a Misc/Web task),
		// activate those packs immediately on Turn 1 without burning a turn on
		// ctf_unlock_toolpack.
		if preRaw, perr := ts.Database().TaskPrecheck(ctx, task); perr == nil && len(preRaw) > 0 {
			var pre ctf.PrecheckResult
			if json.Unmarshal(preRaw, &pre) == nil {
				for _, f := range pre.Files {
					k := strings.ToLower(strings.TrimSpace(f.Kind))
					if k == "elf" || k == "pe" || k == "macho" {
						activePacks[ctfPackBinary] = true
					}
					if k == "pcap" || strings.HasSuffix(strings.ToLower(f.Name), ".pcap") || strings.HasSuffix(strings.ToLower(f.Name), ".pcapng") {
						activePacks[ctfPackCryptoMisc] = true
					}
				}
				for _, tg := range pre.Targets {
					if strings.HasPrefix(tg, "http://") || strings.HasPrefix(tg, "https://") {
						activePacks[ctfPackWeb] = true
					}
				}
				for _, tag := range pre.Tags {
					switch strings.ToLower(strings.TrimSpace(tag)) {
					case "pwn", "reverse", "elf", "pe":
						activePacks[ctfPackBinary] = true
					case "pcap":
						activePacks[ctfPackCryptoMisc] = true
					case "web", "php", "nodejs", "nextjs", "flask", "jinja2", "sql", "ssrf", "ssti", "jwt":
						activePacks[ctfPackWeb] = true
					}
				}
			}
		}
	}
	packs := map[string][]string{}
	var deferred []string
	for _, tl := range built {
		pack := ctfToolPackOf(tl.Name())
		if pack == "" {
			continue
		}
		packs[pack] = append(packs[pack], tl.Name())
		if activePack != ctfPackAll && !activePacks[pack] {
			deferred = append(deferred, tl.Name())
		}
	}
	out = append(out, built...)
	if BenchmarkExtraToolsHook != nil && ts.Database().IsZeroTouchTask(task) {
		out = append(out, BenchmarkExtraToolsHook(ctx, task)...)
	}
	ctx = context.WithValue(ctx, ctfRunKey{}, true)
	if strings.EqualFold(strings.TrimSpace(challenge), "web") {
		ctx = context.WithValue(ctx, ctfWebSkillsKey{}, true)
	}
	if len(deferred) > 0 {
		ctx = context.WithValue(ctx, ctfDeferredKey{}, ctfDeferredVal{
			deferred: deferred,
			unlock:   unlock,
			packs:    packs,
			targets:  &targets,
		})
	}
	return ctx, out
}

func stripCTFPlannerBase(base []actool.CoreTool) []actool.CoreTool {
	out := make([]actool.CoreTool, 0, len(base))
	for _, t := range base {
		name := t.Name()
		if strings.HasPrefix(name, "ctf_") {
			continue
		}
		switch name {
		case "Bash", "Read", "Write", "Edit", "MultiEdit", "Glob", "Grep", "LS", "sleep", "graph_overview", "http_send",
			"http_fuzz_diff", "http_race_probe", "diff_local_remote", "py_repl",
			"ask_helper", "plateau_fork", "benchmark_request_hint", "benchmark_submit_choice",
			"board_mark_savepoint", "board_rewind", "board_save_kit",
			"report_finding", "update_finding_report":
			continue
		}
		out = append(out, t)
	}
	return out
}

// ctfBaseForPlanner scopes the CTF planner strictly to graph/intent/goal orchestration tools,
// withholding shell and execution tools so every technical probe/exploit is dispatched to workers.
func ctfBaseForPlanner(ctx context.Context, ts *db.ExplorationStore, base []actool.CoreTool) (context.Context, []actool.CoreTool) {
	if ts == nil {
		return ctx, base
	}
	mode, _, _, err := ts.TaskInputMetadata()
	if err != nil || !db.IsSandboxTaskMode(mode) {
		return ctx, base
	}
	filtered := stripCTFPlannerBase(base)
	if mode == "ctf" {
		out := make([]actool.CoreTool, 0, len(filtered))
		for _, t := range filtered {
			switch t.Name() {
			case "list_findings", "insert_assets", "list_assets":
				continue
			}
			out = append(out, t)
		}
		filtered = out
	}
	return context.WithValue(ctx, ctfRunKey{}, true), filtered
}

var ctfExecutionTools = []string{"Bash", "Write", "Edit", "Grep", "Glob", "ctf_http", "http_fuzz_diff", "http_race_probe", "diff_local_remote", "py_repl", "ask_helper", "plateau_fork", "benchmark_request_hint", "ctf_binary_info", "ctf_pwn_triage", "ctf_gdb", "ctf_decompile", "ctf_radare2", "Read", "LS", "ctf_tools", "ctf_unlock_toolpack", "ctf_run_background", "ctf_job_status", "ctf_job_stop", "ctf_probe_target", "ctf_session_start", "ctf_session_send", "ctf_session_read", "ctf_session_close", "ctf_pcap_analyze", "board_mark_savepoint", "board_rewind", "board_save_kit"}

func buildCTFGDBScript(userCommands string) string {
	const gdbTailPy = `python
import gdb, json
try:
    inf = gdb.selected_inferior()
    frame = gdb.selected_frame()
    if inf and inf.pid > 0 and frame and frame.is_valid():
        arch = frame.architecture().name()
        is64 = "64" in arch
        word = 8 if is64 else 4
        reg_names = ["rip","rsp","rbp","rax","rbx","rcx","rdx","rsi","rdi"] if is64 else ["eip","esp","ebp","eax","ebx","ecx","edx","esi","edi"]
        regs = {}
        for rn in reg_names:
            try:
                regs[rn] = hex(int(frame.read_register(rn)) & ((1 << (word * 8)) - 1))
            except Exception:
                pass
        sp_val = int(frame.read_register("rsp" if is64 else "esp")) & ((1 << (word * 8)) - 1)
        pc_val = int(frame.read_register("rip" if is64 else "eip")) & ((1 << (word * 8)) - 1)
        align_info = ""
        if is64:
            rem = sp_val & 0xf
            align_info = "16B_ALIGNED" if rem == 0 else f"MISALIGNED(+0x{rem:x} -> MOVAPS risk, consider ret gadget)"
        maps = []
        try:
            with open(f"/proc/{inf.pid}/maps", "r") as mf:
                for line in mf:
                    parts = line.split(None, 5)
                    if len(parts) >= 2:
                        lo_s, hi_s = parts[0].split("-", 1)
                        tag = parts[5].strip() if len(parts) > 5 else "[anon]"
                        maps.append((int(lo_s, 16), int(hi_s, 16), tag))
        except Exception:
            pass
        def tag_addr(val):
            for lo, hi, tag in maps:
                if lo <= val < hi:
                    if "libc" in tag:
                        return f"{tag.split('/')[-1]}+0x{val-lo:x}"
                    if tag.startswith("["):
                        return tag
                    return f"{tag.split('/')[-1]}+0x{val-lo:x}"
            return ""
        stack_top = []
        for idx in range(8):
            addr = sp_val + idx * word
            try:
                raw = inf.read_memory(addr, word)
                val = int.from_bytes(bytes(raw), "little")
                lbl = tag_addr(val)
                stack_top.append(f"+0x{idx*word:02x}: {hex(val)}" + (f" ({lbl})" if lbl else ""))
            except Exception:
                break
        disasm = []
        try:
            for insn in frame.architecture().disassemble(pc_val, count=5):
                disasm.append(f"{hex(insn['addr'])}: {insn['asm']}")
        except Exception:
            pass
        bt = []
        fcur = frame
        for _ in range(5):
            if fcur is None or not fcur.is_valid():
                break
            bt.append(f"#{fcur.level()} {hex(fcur.pc())} {fcur.name() or '?'}")
            fcur = fcur.older()
        print("\n[P3Y_GDB_STATE] " + json.dumps({
            "arch": arch,
            "pc": hex(pc_val),
            "sp": hex(sp_val),
            "stack_alignment": align_info,
            "regs": regs,
            "stack_top": stack_top,
            "disasm_pc": disasm,
            "backtrace": bt,
        }, ensure_ascii=False))
except Exception:
    pass
end`
	lines := strings.Split(strings.ReplaceAll(userCommands, "\r\n", "\n"), "\n")
	var trailing []string
	for len(lines) > 0 {
		last := strings.TrimSpace(lines[len(lines)-1])
		if last == "" || last == "quit" || last == "q" {
			if last != "" {
				trailing = append([]string{last}, trailing...)
			}
			lines = lines[:len(lines)-1]
			continue
		}
		break
	}
	var b strings.Builder
	b.WriteString("set pagination off\nset confirm off\n")
	if body := strings.Join(lines, "\n"); strings.TrimSpace(body) != "" {
		b.WriteString(body)
		b.WriteString("\n")
	}
	b.WriteString(gdbTailPy)
	b.WriteString("\n")
	for _, t := range trailing {
		b.WriteString(t)
		b.WriteString("\n")
	}
	return b.String()
}

func ctfCatalogTools() []actool.CoreTool {
	out := []actool.CoreTool{}
	extraCatalog := map[string]bool{
		"py_repl":              true,
		"http_fuzz_diff":       true,
		"http_race_probe":      true,
		"diff_local_remote":    true,
		"ask_helper":           true,
		"plateau_fork":         true,
		"tips_search":          true,
		"board_mark_savepoint": true,
		"board_rewind":         true,
		"board_save_kit":       true,
	}
	for _, t := range ctfTools(nil, 0, 0, "") {
		if strings.HasPrefix(t.Name(), "ctf_") || extraCatalog[t.Name()] {
			out = append(out, t)
		}
	}
	return out
}
func quote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
func ctfTools(s *ctf.Service, task, intent int64, verifyMode string) []actool.CoreTool {
	return ctfToolsWithUnlock(s, task, intent, verifyMode, nil)
}

// ctfExecToolResult is the compact LLM-facing projection of db.CTFExecution.
// The full record (including command echo, environment, hashes, and the complete
// /work script snapshot array `files`) is still persisted in Postgres for WP/UI,
// but omitting those repeated fields from every tool_result prevents context bloat
// from reaching 100K+ tokens across long solving loops.
type ctfExecToolResult struct {
	ID         string `json:"id"`
	ExitCode   int    `json:"exit_code"`
	Stdout     string `json:"stdout,omitempty"`
	Stderr     string `json:"stderr,omitempty"`
	Error      string `json:"error,omitempty"`
	Truncated  bool   `json:"truncated,omitempty"`
	FilesCount int    `json:"files_count,omitempty"`
}

func formatCTFExecToolResult(e *db.CTFExecution) string {
	if e == nil {
		return "{}"
	}
	res := ctfExecToolResult{
		ID:        e.ID,
		ExitCode:  e.ExitCode,
		Stdout:    e.StdoutExcerpt,
		Stderr:    e.StderrExcerpt,
		Error:     e.Error,
		Truncated: e.Truncated,
	}
	if len(e.Files) > 0 {
		var files []json.RawMessage
		if json.Unmarshal(e.Files, &files) == nil {
			res.FilesCount = len(files)
		}
	}
	b, _ := json.Marshal(res)
	return string(b)
}

func ctfToolsWithUnlock(s *ctf.Service, task, intent int64, verifyMode string, unlockTargets *[]*actool.UnlockSet) []actool.CoreTool {
	run := func(ctx context.Context, command string, timeout int) (actool.Result, error) {
		if s == nil {
			return actool.Errorf("CTF 工具仅在 CTF 任务上下文可用"), nil
		}
		e, err := s.Execute(ctx, task, intent, command, timeout)
		if err != nil {
			return actool.Errorf(err.Error()), nil
		}
		return actool.Text(formatCTFExecToolResult(e)), nil
	}
	commandTool := func(name, desc string, schema map[string]any, build func(map[string]json.RawMessage) (string, int, error)) actool.CoreTool {
		return writeTool(name, desc, schema, func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a map[string]json.RawMessage
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			cmd, timeout, err := build(a)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return run(ctx, cmd, timeout)
		})
	}
	readCommandTool := func(name, desc string, schema map[string]any, build func(map[string]json.RawMessage) (string, int, error)) actool.CoreTool {
		return readTool(name, desc, schema, func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a map[string]json.RawMessage
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			cmd, timeout, err := build(a)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return run(ctx, cmd, timeout)
		})
	}
	httpSchema := obj(map[string]any{
		"url": str("用户提供的完整题目 URL"), "method": str("GET、POST、HEAD、PUT、PATCH、DELETE 或 OPTIONS；有正文时默认 POST"),
		"headers": map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}, "description": "请求头名称与值"},
		"query":   map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}, "description": "自动 URL 编码的查询参数；需要特殊原始编码时直接写入 URL"},
		"form":    map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}, "description": "自动编码的表单字段，不能与 body 同时提供"},
		"body":    str("原始请求正文，最多 64 KiB"), "timeout_seconds": intp("超时秒数，默认 30，最多 120"),
		"follow_redirects": map[string]any{"type": "boolean", "description": "仅当重定向仍属于题目范围时设为 true，最多 3 次"},
		"use_cookies":      map[string]any{"type": "boolean", "description": "保留本意图的 Cookie，默认 true"},
	}, "url")
	text := func(a map[string]json.RawMessage, k string) string {
		var v string
		_ = json.Unmarshal(a[k], &v)
		return v
	}
	num := func(a map[string]json.RawMessage, k string, def int) int {
		var v int
		if json.Unmarshal(a[k], &v) != nil || v <= 0 {
			return def
		}
		return v
	}
	file := func(a map[string]json.RawMessage) (string, error) {
		v := text(a, "file_path")
		if v == "" {
			v = text(a, "path")
		}
		if v == "" {
			return "", fmt.Errorf("缺少文件路径")
		}
		return v, nil
	}
	tools := []actool.CoreTool{
		commandTool("ctf_http", "在本题独立容器中请求 HTTP/HTTPS 题目，保存响应头、正文、状态码及实际执行 ID。响应中的 Flag 自动成为待确认候选；启用流量录制时同步进入 MITM FTS5 流量库。支持 GET/POST、URL 编码 query/form、请求头和意图内 Cookie；默认不跟随重定向，响应上限 8 MiB。", httpSchema, ctfHTTPCommand),
		commandTool("Bash", "在本题专属 Pwn/RE/Web 容器 /work 中执行 Bash。具备 GDB、pwntools（/opt/ctf/pwn/bin/python）、angr/Z3/Unicorn（/opt/ctf/re/bin/python）、Ghidra、radare2 等；日志和脚本自动进入 WP。无法访问 p3y 的配置、密钥或 Docker。超时会终止该容器的进程。", obj(map[string]any{"command": str("命令；附件路径见输入清单"), "timeout": intp("超时毫秒，最多 300000")}, "command"), func(a map[string]json.RawMessage) (string, int, error) {
			return text(a, "command"), min(num(a, "timeout", 120000)/1000, 300), nil
		}),
		commandTool("ctf_binary_info", "真实检查 ELF/PE 架构、依赖、符号及保护；不执行样本。", obj(map[string]any{"path": str("二进制路径")}, "path"), func(a map[string]json.RawMessage) (string, int, error) {
			p, err := file(a)
			return "file -- " + quote(p) + "; readelf -h -l -d -s -- " + quote(p) + "; /opt/ctf/pwn/bin/pwn checksec " + quote(p), 60, err
		}),
		commandTool("ctf_pwn_triage", "【Pwn 首选起手工具】一步完成 ELF/libc 综合测绘：采集 file/架构/stripped/checksec 保护、关键导入函数、Protobuf/Seccomp/堆特征、libc GNU 版本与 BuildID，并匹配本地离线 /opt/ctf/glibc 缓存；默认复制可写二进制到 work_dir 并在命中缓存时自动 patchelf 生成 *_patched。", obj(map[string]any{
			"path":     str("二进制路径（如 /work/.inputs/.../original 或 /work/chall/pwn）"),
			"libc":     str("可选，配套 libc.so.6 路径；留空时自动在同目录与工作区搜索"),
			"work_dir": str("可选，工作目录，默认 /work"),
			"patch":    map[string]any{"type": "boolean", "description": "若命中本地 /opt/ctf/glibc 缓存，是否自动 patchelf 生成 *_patched（默认 true）"},
		}, "path"), func(a map[string]json.RawMessage) (string, int, error) {
			p, err := file(a)
			if err != nil {
				return "", 0, err
			}
			workDir := strings.TrimSpace(text(a, "work_dir"))
			if workDir == "" {
				workDir = "/work"
			}
			args := quote(p) + " --work-dir=" + quote(workDir)
			if libc := strings.TrimSpace(text(a, "libc")); libc != "" {
				args += " --libc=" + quote(libc)
			}
			patch := true
			if rawPatch, ok := a["patch"]; ok {
				var b bool
				if json.Unmarshal(rawPatch, &b) == nil {
					patch = b
				}
			}
			if patch {
				args += " --patch"
			}
			cmd := fmt.Sprintf("if [ -f /opt/ctf/scripts/pwn_triage.py ]; then python3 /opt/ctf/scripts/pwn_triage.py %s; else python3 -c %s %s; fi",
				args, quote(ctf.PwnTriageScript), args)
			return cmd, 90, nil
		}),
		commandTool("ctf_gdb", "以 GDB batch 运行实际调试脚本，可设断点、运行、查看寄存器/栈/反汇编；停止于断点/崩溃时自动附加结构化寄存器、16B 栈对齐校验、栈顶与反汇编摘要面板。保留 .gdb 脚本及输出。", obj(map[string]any{"path": str("样本路径，原始附件先复制到 /work 并 chmod +x"), "commands": str("多行 GDB 命令"), "timeout_seconds": intp("最多 300 秒")}, "path", "commands"), func(a map[string]json.RawMessage) (string, int, error) {
			p, err := file(a)
			script := s.TranslateSandboxWorkPaths(context.Background(), task, intent, buildCTFGDBScript(text(a, "commands")))
			return "printf %s " + quote(base64.StdEncoding.EncodeToString([]byte(script))) + " | base64 -d > debug.gdb\ngdb -q -nx -batch -x debug.gdb -- " + quote(p), num(a, "timeout_seconds", 120), err
		}),
		commandTool("ctf_decompile", "使用 Ghidra headless 实际分析并反编译指定函数，自动启用持久分析缓存（首次全量导入约 15s，后续单函数约 5s）。stripped/复杂逻辑二进制务必优先调用它，而非在 Bash 用 objdump 盲看汇编。函数名为空时取前 5 个函数。", obj(map[string]any{"path": str("二进制路径"), "function": str("函数名，可为空"), "limit": intp("最多 20 个函数")}, "path"), func(a map[string]json.RawMessage) (string, int, error) {
			p, err := file(a)
			limit := min(num(a, "limit", 5), 20)
			fn := text(a, "function")
			cmd := fmt.Sprintf(`h=$(sha256sum -- %s 2>/dev/null | cut -c1-12); [ -z "$h" ] && h="default"; pdir="/tmp/ghidra_$h"; bname=$(basename -- %s); if [ -f "$pdir/proj.gpr" ]; then analyzeHeadless "$pdir" proj -process "$bname" -noanalysis -scriptPath /opt/ctf/scripts -postScript ExportFunctions.java %s %d; else mkdir -p "$pdir"; analyzeHeadless "$pdir" proj -import %s -analysisTimeoutPerFile 180 -scriptPath /opt/ctf/scripts -postScript ExportFunctions.java %s %d; fi`,
				quote(p), quote(p), quote(fn), limit, quote(p), quote(fn), limit)
			return cmd, 300, err
		}),
		commandTool("ctf_radare2", "使用 radare2 执行实际静态分析命令，如 aaa;afl 或 pdf @ main。", obj(map[string]any{"path": str("二进制路径"), "commands": str("radare2 命令")}, "path", "commands"), func(a map[string]json.RawMessage) (string, int, error) {
			p, err := file(a)
			return "r2 -q -e scr.color=0 -c " + quote(text(a, "commands")) + " -c q -- " + quote(p), 120, err
		}),
		readTool("ctf_tools", "检查当前独立执行环境中工具的实际版本及 Python 导入状态。未就绪时返回原因。", obj(nil), func(ctx context.Context, _ json.RawMessage) (actool.Result, error) {
			if s == nil {
				return actool.Errorf("需要 CTF 上下文"), nil
			}
			probeCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
			defer cancel()
			v, err := s.Runner.Health(probeCtx)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			b, _ := json.Marshal(v)
			return actool.Text(string(b)), nil
		}),
		readTool("ctf_status", "读取本题当前输入版本、执行次数和答案状态。候选仍需用户确认；已确认答案不等于任意自定义目标均已完成。返回最近 20 条候选。", obj(nil), func(ctx context.Context, _ json.RawMessage) (actool.Result, error) {
			if s == nil {
				return actool.Errorf("需要 CTF 上下文"), nil
			}
			progress, err := s.Progress(ctx, task)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if len(progress.Candidates) > 20 {
				progress.Candidates = progress.Candidates[:20]
			}
			b, _ := json.Marshal(progress)
			return actool.Text(string(b)), nil
		}),
		writeTool("ctf_submit_flag", "将实际执行输出中的答案登记为候选；零交互自动测评任务会自动提交到平台并即时返回判定结果（多 Flag 题可传入 sub_flag_id）。不能将模型回复直接作为已验证答案。", obj(map[string]any{
			"execution_id": str("真实执行 ID"),
			"value":        str("必须出现在该执行 stdout/stderr 中的答案"),
			"sub_flag_id":  str("可选：多 Flag 题目的子 Flag ID"),
		}, "execution_id", "value"), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a map[string]json.RawMessage
			_ = json.Unmarshal(in, &a)
			if s == nil {
				return actool.Errorf("需要 CTF 上下文"), nil
			}
			id, verdict, err := s.SubmitWithSubFlag(ctx, task, text(a, "execution_id"), text(a, "value"), text(a, "sub_flag_id"))
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if verdict != "" {
				return actool.Text(fmt.Sprintf("已登记候选 #%d 并自动提交至测评平台：%s", id, verdict)), nil
			}
			return actool.Text(fmt.Sprintf("候选 #%d 已登记；尚未确认，请保留脚本与复现步骤。", id)), nil
		}),
		writeTool("benchmark_submit_choice", "专用于零交互自动测评中的客观选择题：提交已确认的选项 ID 数组（如 [\"A\"] 或 [\"A\", \"C\"]）至测评平台验证并获取判定。", obj(map[string]any{
			"choices": map[string]any{
				"type":        "array",
				"items":       map[string]any{"type": "string"},
				"description": "选中的选项 ID 列表，例如 [\"A\"] 或 [\"B\", \"D\"]",
			},
		}, "choices"), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Choices []string `json:"choices"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if BenchmarkChoiceHook == nil || s == nil || s.DB == nil || !s.DB.IsZeroTouchTask(task) {
				return actool.Errorf("当前任务不是零交互自动测评任务，不支持客观选择题提交"), nil
			}
			verdict, handled, err := BenchmarkChoiceHook(ctx, task, a.Choices)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if !handled {
				return actool.Errorf("未找到对应的测评题提交处理器"), nil
			}
			return actool.Text("客观题提交判定结果：" + verdict), nil
		}),
		readTool("benchmark_request_hint", "专用于零交互自动测评：当你已完成活体靶机探测与常规排查、持续受阻（通常需运行满 8 分钟或进入停滞期）时，向赛台主动申请本题官方 Hint（全局幂等，若已拉取过则直接返回缓存；未满 8 分钟且未停滞时会被门禁拒绝以防无谓扣分）。", obj(map[string]any{
			"reason": str("简述你已经排查的方向与当前卡点，说明为何需要官方 Hint"),
		}, "reason"), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a map[string]json.RawMessage
			_ = json.Unmarshal(in, &a)
			if BenchmarkHintHook == nil || s == nil || s.DB == nil || !s.DB.IsZeroTouchTask(task) {
				return actool.Errorf("当前任务无外部测评赛台 Hint 接口可用"), nil
			}
			hintText, handled, err := BenchmarkHintHook(ctx, task, strings.TrimSpace(text(a, "reason")))
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if !handled {
				return actool.Errorf("未找到对应的测评题 Hint 处理器"), nil
			}
			return actool.Text(hintText), nil
		}),
		writeTool("ctf_submit_exploit_proof", "专用于「无需 Flag、需平台裁判机验证」的漏洞利用证明类任务（exploit_proof / flag_and_exploit 第 2 阶段）：将真实执行结果作为利用证明提交，触发自动交接等待用户在赛题平台点击「验证漏洞利用」并确认通过。严禁用于传统仅提交 Flag 的题目，也不能凭空编造未执行的证明。", obj(map[string]any{
			"execution_id":  str("完成并验证利用效果的真实执行 ID（必须有真实输出或脚本产物）"),
			"proof_summary": str("一句中文精准概括已实证达成的漏洞利用效果（如：已越权写入 /data/pwned_proof.txt 并通过二次读取确认持久化）"),
			"target_effect": str("可由平台裁判机校验的具体细节、关键响应或持久化状态说明"),
		}, "execution_id", "proof_summary"), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a map[string]json.RawMessage
			_ = json.Unmarshal(in, &a)
			if s == nil {
				return actool.Errorf("需要 CTF 上下文"), nil
			}
			id, err := s.SubmitExploitProof(ctx, task, text(a, "execution_id"), text(a, "proof_summary"), text(a, "target_effect"))
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text(fmt.Sprintf("漏洞利用证明 #%d 已登记并等待用户在赛题平台验证；请保留复现脚本与证据并交接。", id)), nil
		}),
		writeTool("ctf_run_background", "在独立容器中启动后台长任务（如耗时暴破、深度 Ghidra 反编译、长时间 fuzz 或解题计算），不受 300 秒单次执行超时限制。返回 job_id，后续可通过 ctf_job_status 轮询进展与日志，通过 ctf_job_stop 终止。", obj(map[string]any{
			"command": str("要在后台运行的 Bash 命令"),
			"job_id":  str("任务自定义英文标识（可选，如 crack_zip、ghidra_deep）"),
		}, "command"), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if s == nil {
				return actool.Errorf("需要 CTF 上下文"), nil
			}
			var a map[string]json.RawMessage
			_ = json.Unmarshal(in, &a)
			cmd := text(a, "command")
			if strings.TrimSpace(cmd) == "" {
				return actool.Errorf("command 不能为空"), nil
			}
			jobID := text(a, "job_id")
			info, err := s.StartJob(ctx, task, intent, cmd, jobID)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			b, _ := json.Marshal(info)
			return actool.Text(string(b)), nil
		}),
		readTool("ctf_job_status", "查询后台长任务状态（running / finished / failed / terminated）、退出码及最新输出日志。输出中的 Flag 同样会自动捕获登记为候选。job_id 为空时列出全部后台任务。", obj(map[string]any{
			"job_id":     str("任务标识；若为空则返回所有后台任务列表"),
			"tail_lines": intp("读取日志尾部行数，默认 100，最多 1000"),
		}), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if s == nil {
				return actool.Errorf("需要 CTF 上下文"), nil
			}
			var a map[string]json.RawMessage
			_ = json.Unmarshal(in, &a)
			jobID := text(a, "job_id")
			if strings.TrimSpace(jobID) == "" {
				list, err := s.ListJobs(ctx, task, intent)
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				b, _ := json.Marshal(list)
				return actool.Text(string(b)), nil
			}
			tail := num(a, "tail_lines", 100)
			status, err := s.JobStatus(ctx, task, intent, jobID, tail)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			b, _ := json.Marshal(status)
			return actool.Text(string(b)), nil
		}),
		writeTool("ctf_job_stop", "终止正在运行的后台长任务。", obj(map[string]any{
			"job_id": str("任务标识"),
		}, "job_id"), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if s == nil {
				return actool.Errorf("需要 CTF 上下文"), nil
			}
			var a map[string]json.RawMessage
			_ = json.Unmarshal(in, &a)
			jobID := text(a, "job_id")
			if strings.TrimSpace(jobID) == "" {
				return actool.Errorf("缺少 job_id"), nil
			}
			err := s.StopJob(ctx, task, intent, jobID)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text(fmt.Sprintf("后台任务 %s 已终止", jobID)), nil
		}),
		readTool("ctf_probe_target", "对远程靶机进行网络与协议探测（连通性测试、延迟测定、Banner 抓取、TLS/HTTP 协议识别、Proof-of-Work 挑战检测及交互菜单识别）。支持 'nc 1.2.3.4 9999'、'1.2.3.4:9999'、'http://...' 等格式。连接远程靶机前建议先探测。", obj(map[string]any{
			"target":          str("靶机目标，如 10.10.10.1:9999、nc 10.10.10.1 9999 或 http://10.10.10.1:8080/"),
			"timeout_seconds": intp("探测超时秒数，默认 10，最多 30"),
		}, "target"), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if s == nil {
				return actool.Errorf("需要 CTF 上下文"), nil
			}
			var a map[string]json.RawMessage
			_ = json.Unmarshal(in, &a)
			target := text(a, "target")
			if strings.TrimSpace(target) == "" {
				return actool.Errorf("target 不能为空"), nil
			}
			timeout := min(num(a, "timeout_seconds", 10), 30)
			cmd := fmt.Sprintf("if [ -f /opt/ctf/scripts/probe_target.py ]; then python3 /opt/ctf/scripts/probe_target.py %s --json --timeout=%d; else python3 -c %s %s --timeout=%d; fi",
				quote(target), timeout, quote(ctf.ProbeTargetScript), quote(target), timeout)
			e, err := s.Execute(ctx, task, intent, cmd, timeout+10)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if e.ExitCode != 0 && e.Error != "" {
				return actool.Errorf(fmt.Sprintf("%s: %s", e.Error, e.StderrExcerpt)), nil
			}
			return actool.Text(e.StdoutExcerpt), nil
		}),
		readTool("ctf_pcap_analyze", "对 PCAP / PCAPNG 流量包进行结构化深度分析与证据提取。支持 mode：'summary'（协议分布与 IP 对话摘要）、'http'（提取 HTTP 请求/响应/凭据）、'dns'（DNS 解析与隧道外发分析）、'streams'（TCP 会话列表）、'stream'（跟进指定 stream_id 的双向会话全文）、'export'（一键导出 HTTP 传输文件到 export_dir）、'search'（搜索关键内容或 Flag）、'icmp'（提取 ICMP 数据段隐写）。返回内容中检测到的 Flag 自动登记为候选。", obj(map[string]any{
			"file_path":  str("流量包路径，如 /work/.inputs/.../traffic.pcap"),
			"mode":       str("分析模式：summary / http / dns / streams / stream / export / search / icmp，默认 summary"),
			"stream_id":  intp("当 mode 为 stream 时指定的 TCP stream 编号，默认 0"),
			"filter":     str("可选的 Wireshark 显示过滤表达式，如 'http.request' 或 'tcp.port == 80'"),
			"search":     str("当 mode 为 search 时的搜索关键字或正则，默认 'flag'"),
			"export_dir": str("当 mode 为 export 时的文件导出目标目录，默认 '/work/exported_pcap'"),
		}, "file_path"), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if s == nil {
				return actool.Errorf("需要 CTF 上下文"), nil
			}
			var a map[string]json.RawMessage
			_ = json.Unmarshal(in, &a)
			p, err := file(a)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			mode := text(a, "mode")
			if mode == "" {
				mode = "summary"
			}
			streamID := num(a, "stream_id", 0)
			filt := text(a, "filter")
			searchKw := text(a, "search")
			exportDir := text(a, "export_dir")
			if exportDir == "" {
				exportDir = "/work/exported_pcap"
			}
			args := fmt.Sprintf("%s --mode=%s --stream-id=%d --export-dir=%s", quote(p), quote(mode), streamID, quote(exportDir))
			if filt != "" {
				args += " --filter=" + quote(filt)
			}
			if searchKw != "" {
				args += " --search=" + quote(searchKw)
			}
			cmd := fmt.Sprintf("if [ -f /opt/ctf/scripts/pcap_analyze.py ]; then python3 /opt/ctf/scripts/pcap_analyze.py %s; else python3 -c %s %s; fi",
				args, quote(ctf.PcapAnalyzeScript), args)
			e, err := s.Execute(ctx, task, intent, cmd, 120)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if e.ExitCode != 0 && e.Error != "" {
				return actool.Errorf(fmt.Sprintf("%s: %s", e.Error, e.StderrExcerpt)), nil
			}
			return actool.Text(e.StdoutExcerpt), nil
		}),
		writeTool("ctf_session_start", "启动持久交互终端会话（PTY 伪终端模式），适用于需要多轮交互的 CTF 题目（如 nc 远程靶机、带菜单的本地 Pwn 程序、gdb 交互等）。启动后使用 ctf_session_send 发送输入，使用 ctf_session_read 接收输出。", obj(map[string]any{
			"command":    str("启动命令，如 'nc 10.10.10.1 9999' 或 './vuln'"),
			"session_id": str("会话标识（可选，如 pty1、remote_nc）"),
		}, "command"), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if s == nil {
				return actool.Errorf("需要 CTF 上下文"), nil
			}
			var a map[string]json.RawMessage
			_ = json.Unmarshal(in, &a)
			cmd := text(a, "command")
			if strings.TrimSpace(cmd) == "" {
				return actool.Errorf("command 不能为空"), nil
			}
			sid := text(a, "session_id")
			info, err := s.StartInteractive(ctx, task, intent, cmd, sid)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			b, _ := json.Marshal(info)
			return actool.Text(string(b)), nil
		}),
		writeTool("ctf_session_send", "向正在运行的持久交互会话发送输入数据（如菜单选择编号、用户名、ROP payload 等）。", obj(map[string]any{
			"session_id":   str("会话标识"),
			"data":         str("要发送的数据文本（若为二进制 payload 请设 encoding 为 base64）"),
			"encoding":     str("编码格式：'utf-8' 或 'base64'，默认 utf-8"),
			"auto_newline": map[string]any{"type": "boolean", "description": "是否自动在末尾追加回车换行符 \\n，默认 true"},
		}, "session_id", "data"), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if s == nil {
				return actool.Errorf("需要 CTF 上下文"), nil
			}
			var a map[string]json.RawMessage
			_ = json.Unmarshal(in, &a)
			sid := text(a, "session_id")
			data := text(a, "data")
			encoding := text(a, "encoding")
			if encoding == "" {
				encoding = "utf-8"
			}
			autoNL := true
			if v, ok := a["auto_newline"]; ok {
				_ = json.Unmarshal(v, &autoNL)
			}
			res, err := s.WriteInteractive(ctx, task, intent, sid, data, encoding, autoNL)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			b, _ := json.Marshal(res)
			return actool.Text(string(b)), nil
		}),
		readTool("ctf_session_read", "读取持久交互会话的增量输出内容。输出中的 Flag 会自动捕获登记为候选。session_id 为空时列出所有交互会话。", obj(map[string]any{
			"session_id": str("会话标识；为空时列出所有活跃会话"),
			"offset":     intp("从输出日志的字节偏移量开始读取，默认 0；多轮读取时请传入上一次返回的 offset 以获取增量"),
			"wait_ms":    intp("等待输出的最长毫秒数（100~10000），默认 1000"),
		}), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if s == nil {
				return actool.Errorf("需要 CTF 上下文"), nil
			}
			var a map[string]json.RawMessage
			_ = json.Unmarshal(in, &a)
			sid := text(a, "session_id")
			if strings.TrimSpace(sid) == "" {
				list, err := s.ListInteractive(ctx, task, intent)
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				b, _ := json.Marshal(list)
				return actool.Text(string(b)), nil
			}
			offset := int64(num(a, "offset", 0))
			waitMs := num(a, "wait_ms", 1000)
			res, err := s.ReadInteractive(ctx, task, intent, sid, offset, waitMs)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			b, _ := json.Marshal(res)
			return actool.Text(string(b)), nil
		}),
		writeTool("ctf_session_close", "终止并关闭指定的持久交互会话。", obj(map[string]any{
			"session_id": str("要关闭的会话标识"),
		}, "session_id"), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if s == nil {
				return actool.Errorf("需要 CTF 上下文"), nil
			}
			var a map[string]json.RawMessage
			_ = json.Unmarshal(in, &a)
			sid := text(a, "session_id")
			if strings.TrimSpace(sid) == "" {
				return actool.Errorf("缺少 session_id"), nil
			}
			err := s.CloseInteractive(ctx, task, intent, sid)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text(fmt.Sprintf("交互会话 %s 已关闭", sid)), nil
		}),
	}
	// File tools use the same container and evidence recorder as Bash. No local
	// application file reader is exposed, including on resumed conversations.
	scopedPath := func(a map[string]json.RawMessage) (string, error) {
		p, err := file(a)
		if err != nil {
			return "", err
		}
		if !path.IsAbs(p) {
			p = path.Join("/work", p)
		}
		if p != "/work" && !strings.HasPrefix(path.Clean(p), "/work/") {
			return "", fmt.Errorf("文件工具仅允许 /work 工作区与 /work/.inputs 附件")
		}
		return path.Clean(p), nil
	}
	tools = append(tools,
		commandTool("Read", "读取本题 /work 下的文本文件或附件，二进制请用 Bash xxd/readelf。", obj(map[string]any{"file_path": str("/work 内路径"), "offset": intp("起始行，默认 1"), "limit": intp("最多 500 行")}, "file_path"), func(a map[string]json.RawMessage) (string, int, error) {
			p, err := scopedPath(a)
			start := num(a, "offset", 1)
			return fmt.Sprintf("sed -n '%d,%dp' -- %s", start, start+min(num(a, "limit", 200), 500)-1, quote(p)), 30, err
		}),
		commandTool("Write", "将文本写入本题 /work 工作区，脚本自动纳入 WP 证据。", obj(map[string]any{"file_path": str("/work 内路径"), "content": str("文本")}, "file_path", "content"), func(a map[string]json.RawMessage) (string, int, error) {
			p, err := scopedPath(a)
			if strings.HasPrefix(p, "/work/.inputs") {
				err = fmt.Errorf("原始附件只读，请复制到工作区")
			}
			content := s.TranslateSandboxWorkPaths(context.Background(), task, intent, text(a, "content"))
			return "mkdir -p -- " + quote(path.Dir(p)) + "; printf %s " + quote(base64.StdEncoding.EncodeToString([]byte(content))) + " | base64 -d > " + quote(p), 30, err
		}),
		commandTool("Edit", "精准修改本题 /work 工作区内的文本文件（如调整 exp.py 偏移或脚本参数），避免重写整文件。", obj(map[string]any{
			"file_path":   str("/work 内路径"),
			"old_string":  str("要替换的精确原文本片段"),
			"new_string":  str("替换后的新文本"),
			"replace_all": map[string]any{"type": "boolean", "description": "是否替换全部匹配（默认 false，要求唯一匹配）"},
		}, "file_path", "old_string", "new_string"), func(a map[string]json.RawMessage) (string, int, error) {
			p, err := scopedPath(a)
			if err != nil {
				return "", 30, err
			}
			if strings.HasPrefix(p, "/work/.inputs") {
				return "", 30, fmt.Errorf("原始附件只读，请复制到工作区")
			}
			oldStr := s.TranslateSandboxWorkPaths(context.Background(), task, intent, text(a, "old_string"))
			newStr := s.TranslateSandboxWorkPaths(context.Background(), task, intent, text(a, "new_string"))
			if oldStr == "" {
				return "", 30, fmt.Errorf("old_string 不能为空")
			}
			if oldStr == newStr {
				return "", 30, fmt.Errorf("new_string 与 old_string 相同")
			}
			replaceAll := false
			if rawAll, ok := a["replace_all"]; ok {
				_ = json.Unmarshal(rawAll, &replaceAll)
			}
			py := `import base64, os, sys
p = sys.argv[1]
old = base64.b64decode(sys.argv[2]).decode("utf-8")
new = base64.b64decode(sys.argv[3]).decode("utf-8")
rep_all = sys.argv[4] == "1"
if not os.path.isfile(p):
    sys.stderr.write(f"file not found: {p}\n")
    sys.exit(2)
with open(p, "r", encoding="utf-8") as f:
    data = f.read()
cnt = data.count(old)
if cnt == 0:
    sys.stderr.write("old_string not found in file\n")
    sys.exit(3)
if not rep_all and cnt > 1:
    sys.stderr.write(f"old_string matched {cnt} times; provide more context or set replace_all=true\n")
    sys.exit(4)
updated = data.replace(old, new) if rep_all else data.replace(old, new, 1)
tmp = p + ".p3y.tmp"
with open(tmp, "w", encoding="utf-8") as f:
    f.write(updated)
os.replace(tmp, p)
print(f"edited {p} ({cnt if rep_all else 1} replacement(s))")`
			allFlag := "0"
			if replaceAll {
				allFlag = "1"
			}
			cmd := fmt.Sprintf("python3 -c %s %s %s %s %s",
				quote(py),
				quote(p),
				quote(base64.StdEncoding.EncodeToString([]byte(oldStr))),
				quote(base64.StdEncoding.EncodeToString([]byte(newStr))),
				quote(allFlag),
			)
			return cmd, 30, nil
		}),
		readCommandTool("Grep", "在本题 /work 工作区或 /work/.inputs 中检索文本/符号（优先 rg，自动跳过缓存目录）。", obj(map[string]any{
			"pattern":     str("要搜索的正则或文本模式"),
			"path":        str("/work 内搜索目录或文件路径，默认 /work"),
			"glob":        str("可选文件名过滤，如 *.py 或 *.c"),
			"ignore_case": map[string]any{"type": "boolean", "description": "是否忽略大小写"},
			"max_results": intp("最多返回行数，默认 50，最多 200"),
		}, "pattern"), func(a map[string]json.RawMessage) (string, int, error) {
			if text(a, "path") == "" && text(a, "file_path") == "" {
				a["path"] = json.RawMessage(`"/work"`)
			}
			p, err := scopedPath(a)
			if err != nil {
				return "", 30, err
			}
			pat := text(a, "pattern")
			if strings.TrimSpace(pat) == "" {
				return "", 30, fmt.Errorf("pattern 不能为空")
			}
			maxRes := min(num(a, "max_results", 50), 200)
			var ig bool
			if rawIC, ok := a["ignore_case"]; ok {
				_ = json.Unmarshal(rawIC, &ig)
			}
			globPat := strings.TrimSpace(text(a, "glob"))
			rgFlags := "-n --no-heading"
			grepFlags := "-rnE"
			if ig {
				rgFlags += " -i"
				grepFlags += " -i"
			}
			if globPat != "" {
				rgFlags += " -g " + quote(globPat)
				grepFlags += " --include=" + quote(globPat)
			}
			cmd := fmt.Sprintf(
				"if command -v rg >/dev/null 2>&1; then rg %s -g '!.snapshots/**' -g '!.ghidra/**' -g '!.cache/**' -g '!.jobs/**' -g '!.interactive/**' -- %s %s; else grep %s --exclude-dir=.snapshots --exclude-dir=.ghidra --exclude-dir=.cache --exclude-dir=.jobs --exclude-dir=.interactive -- %s %s; fi | head -n %d || true",
				rgFlags, quote(pat), quote(p), grepFlags, quote(pat), quote(p), maxRes,
			)
			return cmd, 30, nil
		}),
		readCommandTool("Glob", "按通配符列出本题 /work 工作区或 /work/.inputs 中的文件。", obj(map[string]any{
			"pattern":     str("匹配模式，如 *.py、**/*.elf 或 libc*"),
			"path":        str("/work 内根目录，默认 /work"),
			"max_results": intp("最多返回文件路径数，默认 100，最多 500"),
		}, "pattern"), func(a map[string]json.RawMessage) (string, int, error) {
			if text(a, "path") == "" && text(a, "file_path") == "" {
				a["path"] = json.RawMessage(`"/work"`)
			}
			p, err := scopedPath(a)
			if err != nil {
				return "", 30, err
			}
			pat := strings.TrimSpace(text(a, "pattern"))
			if pat == "" {
				return "", 30, fmt.Errorf("pattern 不能为空")
			}
			maxRes := min(num(a, "max_results", 100), 500)
			py := `import pathlib, sys
root = pathlib.Path(sys.argv[1])
pat = sys.argv[2]
cap = int(sys.argv[3])
skip = {".snapshots", ".ghidra", ".cache", ".jobs", ".interactive", ".git"}
it = root.glob(pat) if ("/" in pat or pat.startswith("**")) else root.rglob(pat)
out = []
for item in sorted(it):
    if any(part in skip for part in item.parts):
        continue
    out.append(str(item))
    if len(out) >= cap:
        break
print("\n".join(out))`
			return fmt.Sprintf("python3 -c %s %s %s %d", quote(py), quote(p), quote(pat), maxRes), 30, nil
		}),
		commandTool("LS", "列出本题 /work 工作区文件。", obj(map[string]any{"path": str("/work 内目录，默认 /work")}), func(a map[string]json.RawMessage) (string, int, error) {
			if text(a, "path") == "" {
				a["path"] = json.RawMessage(`"/work"`)
			}
			p, err := scopedPath(a)
			return "ls -lah -- " + quote(p), 30, err
		}),
		writeTool("ctf_unlock_toolpack", "当当前题型需要跨领域工具时按需解锁对应工具包（例如 Web 题遇到 ELF 附件需解锁 binary，或 Pwn 题需要 Web/流量分析工具）。可选 pack：binary (ctf_binary_info/ctf_pwn_triage/ctf_gdb/ctf_decompile/ctf_radare2)、web (ctf_http/http_fuzz_diff/http_race_probe)、crypto_misc (ctf_pcap_analyze)、all。", obj(map[string]any{
			"pack": str("要解锁的领域工具包：binary | web | crypto_misc | all"),
		}, "pack"), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a map[string]json.RawMessage
			_ = json.Unmarshal(in, &a)
			pack := strings.ToLower(strings.TrimSpace(text(a, "pack")))
			packTools := map[string][]string{
				ctfPackBinary:     {"ctf_binary_info", "ctf_pwn_triage", "ctf_gdb", "ctf_decompile", "ctf_radare2", "diff_local_remote"},
				ctfPackWeb:        {"ctf_http", "http_fuzz_diff", "http_race_probe"},
				ctfPackCryptoMisc: {"ctf_pcap_analyze"},
			}
			var unlockNames []string
			switch pack {
			case ctfPackBinary, ctfPackWeb, ctfPackCryptoMisc:
				unlockNames = packTools[pack]
			case ctfPackAll:
				for _, names := range packTools {
					unlockNames = append(unlockNames, names...)
				}
			default:
				return actool.Errorf(fmt.Sprintf("未知工具包 %q，可选: binary | web | crypto_misc | all", pack)), nil
			}
			if unlockTargets != nil {
				for _, u := range *unlockTargets {
					if u != nil {
						u.Add(unlockNames...)
					}
				}
			}
			return actool.Text(fmt.Sprintf("已解锁工具包 %s: %s（下轮起可直接调用）", pack, strings.Join(unlockNames, ", "))), nil
		}),
	)
	var pg *db.DB
	if s != nil {
		pg = s.DB
	}
	tools = append(tools, ctfBoardTools(s, pg, task, intent)...)
	tools = append(tools, ctfNeuroTools(s, task, intent)...)
	tools = append(tools, askHelperTool(), plateauForkTool())
	filtered := make([]actool.CoreTool, 0, len(tools))
	zeroTouch := s != nil && s.DB != nil && s.DB.IsZeroTouchTask(task)
	for _, tl := range tools {
		if (tl.Name() == "benchmark_submit_choice" || tl.Name() == "benchmark_request_hint") && !zeroTouch {
			continue
		}
		if verifyMode == "ad_none" && (tl.Name() == "ctf_submit_flag" || tl.Name() == "ctf_submit_exploit_proof") {
			continue
		}
		if verifyMode == db.CTFVerifyExploitProof && tl.Name() == "ctf_submit_flag" {
			continue
		}
		if verifyMode == db.CTFVerifyFlag && tl.Name() == "ctf_submit_exploit_proof" {
			continue
		}
		filtered = append(filtered, tl)
	}
	return filtered
}

// ctfRunBudgetForTask ensures non-recon Lead-Solver intents have at least a 20m
// continuous wall-clock budget (and 30m for multi-stage CTF tasks after the first
// verified flag), while keeping recon intents bounded.
func ctfRunBudgetForTask(ctx context.Context, workDir string, ts *db.ExplorationStore, taskID int64, phase string, base time.Duration) time.Duration {
	if base <= 0 || phase == "recon" || ts == nil || taskID <= 0 {
		return base
	}
	if base < 20*time.Minute {
		base = 20 * time.Minute
	}
	if base >= 30*time.Minute {
		return base
	}
	pg := ts.Database()
	if pg == nil {
		return base
	}
	prog, err := ctf.New(workDir, pg).Progress(ctx, taskID)
	if err == nil && prog.AcceptedFlagCount >= 1 {
		return 30 * time.Minute
	}
	return base
}

// Legacy run-directory instructions are superseded by the CTF execution scope.
func ctfPrompt(root string, task, intent int64) string {
	return fmt.Sprintf(`

【CTF 专用流程：取得候选 → 交给用户提交验证】
Bash 和文件工具只在独立容器 /work 执行；脚本写在 /work。应用目录 %s 仅为归档路径。
工具使用与解题方法请参考后文的【题型专精求解指引】。仅工具缺失或异常时使用 ctf_tools 体检，不要每轮重复检查环境。
远程靶机访问：在连接远程靶机（如 nc 1.2.3.4 9999 或 http 端口）前，先使用 ctf_probe_target 探测连通性、RTT、初始 Banner、TLS 以及是否有 Proof-of-Work (PoW) 校验。
流量包分析：遇到 .pcap / .pcapng 题目时，优先使用 ctf_pcap_analyze 进行多模式结构化提取（summary 把握全貌、http/dns 审计协议与外发、export 一键导出传输文件、stream 跟踪 TCP 对话、search 快速检索 Flag、icmp 提取隐写载荷）。
多轮交互挑战：对于需要交互菜单选择、多轮 stdin 输入或动态交互的靶机/本地程序，请使用 ctf_session_start 启动持久 PTY 会话，使用 ctf_session_send 发送多轮输入，使用 ctf_session_read 接收输出（输出中的 Flag 同样会自动提取并登记候选），结束时调用 ctf_session_close。
长耗时任务（如大型程序 Ghidra 反编译、密码字典暴破、全路径符号执行等预计超过 2 分钟的任务）请使用 ctf_run_background 后台运行，并用 ctf_job_status 轮询结果与日志，避免单个命令超时。
大体积文件处理：解压超过 64 MiB 的大型中间产物（如巨型 docx/xml、固件镜像、大型流量包等）建议直接解压至 /tmp 下分析，仅将解题脚本与关键结果保存在 /work。
执行自动保存命令、输出、脚本及 execution_id：
- 若本题需要 Flag：常见 Flag 自动登记候选；非标准格式才需 ctf_submit_flag，且必须来自真实执行输出。
- 若本题为「漏洞利用证明（无需 Flag）」或「复合验收第 2 阶段」：在目标环境实际完成利用并通过二次验证确认效果持久化后，调用 ctf_submit_exploit_proof 提交证明（必须绑定真实 execution_id 与实际验证细节）。
一旦提交候选或证明（零交互多 Flag 题目且平台回执 completed=false 尚有剩余 Flag 未拿齐时除外——此时严禁停手，须留在当前意图继续向下一阶段推进），立即停止探测、重复 payload、资产扩展、漏洞报告和目标证明；只交付核心结论与来源执行，等待用户到赛题平台验证。WP 无需额外模型整理。
候选不是最终通过结论：用户确认后才引用已确认记录证明对应目标；用户否定后按反馈继续，避免再次提交同一被否定答案。
分析步骤不拆成必须验收的目标；多阶段或多 Flag 交付按题干要求与用户确认状态推进。`, filepath.Join(root, "tasks", fmt.Sprint(task), fmt.Sprintf("i%d", intent)))
}
