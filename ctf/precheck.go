package ctf

import (
	"archive/zip"
	"bytes"
	"context"
	"debug/elf"
	"debug/pe"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"p3y/artifacts"
	"p3y/db"
)

// PrecheckFile captures zero-LLM static metadata about one task attachment.
type PrecheckFile struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	LogicalPath string            `json:"logical_path"`
	Size        int64             `json:"size"`
	SHA256      string            `json:"sha256"`
	Kind        string            `json:"kind"`
	Arch        string            `json:"arch,omitempty"`
	Protections map[string]any    `json:"protections,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
	Notes       string            `json:"notes,omitempty"`
}

// PrecheckResult stores the Phase-0 deterministic triage sheet for a CTF task.
type PrecheckResult struct {
	TaskID                   int64          `json:"task_id"`
	InputHash                string         `json:"input_hash"`
	ChallengeType            string         `json:"challenge_type"`
	InferredCategory         string         `json:"inferred_category"`
	Targets                  []string       `json:"targets,omitempty"`
	Tags                     []string       `json:"tags,omitempty"`
	Files                    []PrecheckFile `json:"files,omitempty"`
	MatchedTips              []db.TipCard   `json:"matched_tips,omitempty"`
	BaselinePlaceholderFlags []string       `json:"baseline_placeholder_flags,omitempty"`
	Summary                  string         `json:"summary"`
	GeneratedAt              time.Time      `json:"generated_at"`
}

var (
	reURLTarget = regexp.MustCompile(`https?://[^\s"'<>()\[\]]+`)
	reNCTarget  = regexp.MustCompile(`(?i)\bnc\s+([a-zA-Z0-9._-]+)\s+(\d{1,5})\b`)
	reIPPort    = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}:\d{1,5}\b`)
)

func extractTargets(texts ...string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(v string) {
		v = strings.TrimSpace(strings.TrimRight(v, ".,;:)"))
		if v == "" || seen[v] {
			return
		}
		seen[v] = true
		out = append(out, v)
	}
	for _, t := range texts {
		for _, m := range reURLTarget.FindAllString(t, -1) {
			add(m)
		}
		for _, m := range reNCTarget.FindAllStringSubmatch(t, -1) {
			if len(m) == 3 {
				add("nc " + m[1] + " " + m[2])
			}
		}
		for _, m := range reIPPort.FindAllString(t, -1) {
			add(m)
		}
	}
	return out
}

type textTagRule struct {
	tag          string
	needles      []string
	wordBoundary bool
}

var sharedTextTagRules = []textTagRule{
	{tag: "nextjs", needles: []string{"nextjs", "next.js", "_next", "x-middleware-subrequest"}},
	{tag: "middleware", needles: []string{"middleware", "中间件"}},
	{tag: "ssrf", needles: []string{"ssrf", "server-side request", "服务端请求伪造"}},
	{tag: "react", needles: []string{"react", "reactjs", "flight", "next.js", "rsc"}, wordBoundary: true},
	{tag: "rsc", needles: []string{"react flight", "flight 协议", "next-action", "cve-2025-55182", "rsc"}, wordBoundary: true},
	{tag: "nodejs", needles: []string{"node.js", "nodejs", "express", "nextjs"}},
	{tag: "nginx", needles: []string{"nginx", "x-accel-redirect"}},
	{tag: "php", needles: []string{"php", "php_serialize", ".php"}},
	{tag: "session", needles: []string{"session", "phpsessid", "session_upload_progress"}},
	{tag: "unserialize", needles: []string{"unserialize", "反序列化", "php_serialize"}},
	{tag: "lfi", needles: []string{"lfi", "php://filter", "include(", "文件包含"}, wordBoundary: true},
	{tag: "filter_chain", needles: []string{"php://filter", "filter chain", "filter_chain"}},
	{tag: "postgres", needles: []string{"postgres", "postgresql", "pg_read_file", "dblink"}},
	{tag: "dblink", needles: []string{"dblink"}},
	{tag: "sql", needles: []string{"sql", "sqli", "注入", "postgres", "mysql", "sqlite"}},
	{tag: "waf", needles: []string{"waf", "防火墙", "拦截"}, wordBoundary: true},
	{tag: "python", needles: []string{"python", "bottle", "flask", "jinja", "werkzeug"}},
	{tag: "bottle", needles: []string{"bottle"}},
	{tag: "jinja2", needles: []string{"jinja", "flask"}},
	{tag: "handlebars", needles: []string{"handlebars", "mustachestatement", "numberliteral"}},
	{tag: "ssti", needles: []string{"ssti", "模板注入", "template injection", "bottle", "jinja", "handlebars"}},
	{tag: "jwt", needles: []string{"jwt", "jsonwebtoken", "alg=none", "eyjhb", "resettoken"}, wordBoundary: true},
	{tag: "ldaps", needles: []string{"ldaps", "ldap://", "ldaps://"}, wordBoundary: true},
	{tag: "jndi", needles: []string{"jndi", "beanfactory", "elprocessor"}, wordBoundary: true},
	{tag: "tls", needles: []string{"tls", "sni", "自签证书", "sslcontext", "ssl=true"}, wordBoundary: true},
	{tag: "android", needles: []string{"android", "androidmanifest", ".apk", "apk"}},
	{tag: "axml", needles: []string{"axml", "androidmanifest"}, wordBoundary: true},
	{tag: "dex", needles: []string{"classes.dex", "dalvik", "dex"}, wordBoundary: true},
	{tag: "minecraft", needles: []string{"minecraft", "mcproto", "aes-cfb8"}},
	{tag: "pcap", needles: []string{"pcap", "pcapng", "流量包", "tshark"}},
	{tag: "portscan", needles: []string{"端口扫描", "全端口", "nmap", "masscan", "portscan"}},
	{tag: "tunnel", needles: []string{"端口转发", "隧道", "跳板", "内网穿透", "socks5", "proxychains", "tcp_fwd", "tunnel"}},
	{tag: "pivot", needles: []string{"内网横向", "二层网段", "深层网段", "跳板", "pivot"}},
	{tag: "captcha", needles: []string{"captcha", "验证码"}},
	{tag: "pow", needles: []string{"proof of work", "工作量证明", "pow"}},
	{tag: "race_condition", needles: []string{"race condition", "race_condition", "竞态", "并发", "双花"}},
	{tag: "pwn", needles: []string{"pwn", "rop", "glibc", "seccomp", "execve", "shellcode", "heap", "llvm", "rustc", "uaf"}},
	{tag: "reverse", needles: []string{"reverse", "逆向", "crackme", "反编译", "decompile"}},
	{tag: "crypto", needles: []string{"crypto", "密码", "3pc", "mpc", "mp-spdz", "elliptic", "lattice", "lwe", "rsa"}},
}

func isASCIIAlphaNum(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

func containsNeedleWithBoundary(text, needle string, wordBoundary bool) bool {
	if !wordBoundary {
		return strings.Contains(text, needle)
	}
	checkLeft := len(needle) > 0 && isASCIIAlphaNum(needle[0])
	checkRight := len(needle) > 0 && isASCIIAlphaNum(needle[len(needle)-1])
	if !checkLeft && !checkRight {
		return strings.Contains(text, needle)
	}
	for off := 0; off < len(text); {
		idx := strings.Index(text[off:], needle)
		if idx < 0 {
			return false
		}
		start := off + idx
		end := start + len(needle)
		leftOK := !checkLeft || start == 0 || !isASCIIAlphaNum(text[start-1])
		rightOK := !checkRight || end == len(text) || !isASCIIAlphaNum(text[end])
		if leftOK && rightOK {
			return true
		}
		off = start + 1
	}
	return false
}

var negativeClauseMarkers = []string{
	"不碰", "不重复", "已排除", "排除", "正交", "刻意区分", "区别于",
	"勿测", "避免", "并非", "不再", "跳过", "独立于", "无需", "不走",
}

func hasNegativeClauseMarker(s string) bool {
	for _, m := range negativeClauseMarkers {
		if strings.Contains(s, m) {
			return true
		}
	}
	return false
}

// stripNegativeClauses drops parenthetical remarks and short comma/semicolon
// segments containing exclusion cues (e.g. "（与 #2096 SSH 爆破正交，不重复）")
// so rejected techniques never re-trigger mid-run tip recall.
func stripNegativeClauses(s string) string {
	var cleanParens strings.Builder
	runes := []rune(s)
	for i := 0; i < len(runes); {
		r := runes[i]
		if r == '(' || r == '（' {
			depth := 1
			j := i + 1
			for j < len(runes) && depth > 0 {
				if runes[j] == '(' || runes[j] == '（' {
					depth++
				} else if runes[j] == ')' || runes[j] == '）' {
					depth--
				}
				j++
			}
			block := string(runes[i:j])
			if hasNegativeClauseMarker(block) {
				cleanParens.WriteByte(' ')
			} else {
				cleanParens.WriteString(block)
			}
			i = j
			continue
		}
		cleanParens.WriteRune(r)
		i++
	}
	clauses := strings.FieldsFunc(cleanParens.String(), func(r rune) bool {
		return r == '。' || r == '；' || r == ';' || r == '\n' || r == '，' || r == ','
	})
	kept := make([]string, 0, len(clauses))
	for _, cl := range clauses {
		if hasNegativeClauseMarker(cl) {
			continue
		}
		kept = append(kept, cl)
	}
	return strings.Join(kept, " ")
}

// ExtractTextTags extracts canonical technique/framework tags from arbitrary text.
func ExtractTextTags(texts ...string) []string {
	joined := strings.ToLower(strings.Join(texts, "\n"))
	var out []string
	for _, r := range sharedTextTagRules {
		for _, nd := range r.needles {
			if containsNeedleWithBoundary(joined, nd, r.wordBoundary) {
				out = append(out, r.tag)
				break
			}
		}
	}
	return out
}

// ExtractIntentTags strips orthogonal/exclusion clauses from Planner intent descriptions
// before extracting specific technique tags for mid-run secondary tip recall.
func ExtractIntentTags(texts ...string) []string {
	cleaned := make([]string, 0, len(texts))
	for _, t := range texts {
		if s := strings.TrimSpace(stripNegativeClauses(t)); s != "" {
			cleaned = append(cleaned, s)
		}
	}
	if len(cleaned) == 0 {
		return nil
	}
	return ExtractTextTags(cleaned...)
}

func extractTextTags(texts ...string) []string {
	return ExtractTextTags(texts...)
}

func inspectArtifactFile(a artifacts.Artifact, diskPath string) PrecheckFile {
	pf := PrecheckFile{
		ID:          a.ID,
		Name:        a.Name,
		LogicalPath: (&Service{}).LogicalPath(a),
		Size:        a.Size,
		SHA256:      a.SHA256,
		Kind:        "unknown",
	}
	tagSet := map[string]bool{}
	addTag := func(t string) {
		t = strings.ToLower(strings.TrimSpace(t))
		if t != "" {
			tagSet[t] = true
		}
	}

	rawHeader := make([]byte, 65536)
	if f, err := os.Open(diskPath); err == nil {
		n, _ := f.Read(rawHeader)
		rawHeader = rawHeader[:n]
		_ = f.Close()
	}

	ext := strings.ToLower(filepath.Ext(a.Name))
	lowerName := strings.ToLower(a.Name)

	// 1. ELF inspection
	if bytes.HasPrefix(rawHeader, []byte{0x7f, 'E', 'L', 'F'}) {
		pf.Kind = "elf"
		addTag("elf")
		if ef, err := elf.Open(diskPath); err == nil {
			defer ef.Close()
			switch ef.Machine {
			case elf.EM_X86_64:
				pf.Arch = "amd64"
			case elf.EM_386:
				pf.Arch = "i386"
			case elf.EM_AARCH64:
				pf.Arch = "arm64"
			case elf.EM_ARM:
				pf.Arch = "arm"
			default:
				pf.Arch = ef.Machine.String()
			}
			addTag(pf.Arch)

			pie := ef.Type == elf.ET_DYN
			nx := true
			relro := "none"
			hasDyn := false
			hasBindNow := false
			for _, p := range ef.Progs {
				switch p.Type {
				case elf.PT_DYNAMIC:
					hasDyn = true
				case elf.PT_GNU_STACK:
					if p.Flags&elf.PF_X != 0 {
						nx = false
					}
				case elf.PT_GNU_RELRO:
					relro = "partial"
				}
			}
			if dynSyms, _ := ef.DynamicSymbols(); len(dynSyms) > 0 {
				_ = dynSyms
			}
			if vals, err := ef.DynValue(elf.DT_BIND_NOW); err == nil && len(vals) > 0 {
				hasBindNow = true
			}
			if vals, err := ef.DynValue(elf.DT_FLAGS); err == nil {
				for _, v := range vals {
					if v&uint64(elf.DF_BIND_NOW) != 0 {
						hasBindNow = true
					}
				}
			}
			if relro == "partial" && hasBindNow {
				relro = "full"
			}
			stripped := ef.Section(".symtab") == nil
			canary := false
			if syms, err := ef.DynamicSymbols(); err == nil {
				for _, sym := range syms {
					if strings.Contains(sym.Name, "__stack_chk_fail") {
						canary = true
						break
					}
				}
			}
			isLibc := strings.Contains(lowerName, "libc")
			if isLibc {
				addTag("libc_provided")
				addTag("libc")
			}
			pf.Protections = map[string]any{
				"pie":      pie,
				"nx":       nx,
				"relro":    relro,
				"canary":   canary,
				"stripped": stripped,
				"dynamic":  hasDyn,
				"is_libc":  isLibc,
			}
			if !pie && !isLibc {
				addTag("no_pie")
			}
			if canary {
				addTag("canary")
			}
			if stripped {
				addTag("stripped")
			}
			pf.Notes = fmt.Sprintf("ELF %s | PIE=%t NX=%t RELRO=%s Canary=%t Stripped=%t", pf.Arch, pie, nx, relro, canary, stripped)
		}
	} else if bytes.HasPrefix(rawHeader, []byte{'M', 'Z'}) {
		if pfPE, err := pe.Open(diskPath); err == nil {
			defer pfPE.Close()
			pf.Kind = "pe"
			addTag("pe")
			if pfPE.Machine == pe.IMAGE_FILE_MACHINE_AMD64 {
				pf.Arch = "amd64"
			} else if pfPE.Machine == pe.IMAGE_FILE_MACHINE_I386 {
				pf.Arch = "i386"
			}
			addTag(pf.Arch)
			pf.Notes = "PE " + pf.Arch
		}
	} else if len(rawHeader) >= 4 && (bytes.HasPrefix(rawHeader, []byte{0xd4, 0xc3, 0xb2, 0xa1}) || bytes.HasPrefix(rawHeader, []byte{0xa1, 0xb2, 0xc3, 0xd4}) || bytes.HasPrefix(rawHeader, []byte{0x0a, 0x0d, 0x0d, 0x0a})) {
		pf.Kind = "pcap"
		addTag("pcap")
		pf.Notes = "PCAP/PCAPNG packet capture"
	} else if bytes.HasPrefix(rawHeader, []byte{'P', 'K', 0x03, 0x04}) {
		pf.Kind = "zip"
		addTag("zip")
		if ext == ".docx" || ext == ".xlsx" || ext == ".pptx" {
			addTag("office_doc")
		}
		if zr, err := zip.OpenReader(diskPath); err == nil {
			defer zr.Close()
			enc := false
			inspected := 0
			for _, f := range zr.File {
				if f.Flags&0x1 != 0 {
					enc = true
				}
				if f.FileInfo().IsDir() || f.Flags&0x1 != 0 || inspected >= 16 || f.UncompressedSize64 > 32<<20 {
					continue
				}
				inspected++
				lname := strings.ToLower(f.Name)
				if strings.Contains(lname, "libc") && strings.Contains(lname, ".so") {
					addTag("libc_provided")
				}
				if strings.HasSuffix(lname, ".pcap") || strings.HasSuffix(lname, ".pcapng") {
					addTag("pcap")
				}
				if rc, oerr := f.Open(); oerr == nil {
					var magic [4]byte
					n, _ := io.ReadFull(rc, magic[:])
					_ = rc.Close()
					if n >= 4 && bytes.Equal(magic[:4], []byte{0x7f, 'E', 'L', 'F'}) {
						addTag("elf")
					} else if n >= 2 && bytes.Equal(magic[:2], []byte{'M', 'Z'}) {
						addTag("pe")
					}
				}
			}
			if enc {
				addTag("zip_encrypted")
			}
			pf.Notes = fmt.Sprintf("ZIP entries=%d encrypted=%t", len(zr.File), enc)
		}
	} else if bytes.HasPrefix(rawHeader, []byte{0x89, 'P', 'N', 'G'}) || bytes.HasPrefix(rawHeader, []byte{0xff, 0xd8, 0xff}) || bytes.HasPrefix(rawHeader, []byte{'G', 'I', 'F', '8'}) {
		pf.Kind = "image"
		addTag("image")
		addTag("stego")
		pf.Notes = "Image asset"
	} else {
		switch ext {
		case ".py", ".sage", ".php", ".js", ".ts", ".c", ".cpp", ".go", ".rb":
			pf.Kind = "script"
			addTag(strings.TrimPrefix(ext, "."))
		default:
			if len(rawHeader) > 0 && !bytes.Contains(rawHeader, []byte{0}) {
				pf.Kind = "text"
			} else {
				pf.Kind = "binary"
			}
		}
		lowerBody := strings.ToLower(string(rawHeader))
		if strings.Contains(lowerBody, "rsa") || strings.Contains(lowerBody, "gmpy2") || strings.Contains(lowerBody, "crypto.util") || strings.Contains(lowerBody, "aes") {
			addTag("crypto")
			if strings.Contains(lowerBody, "rsa") {
				addTag("rsa")
			}
		}
		if strings.Contains(lowerBody, "<?php") || strings.Contains(lowerBody, "flask") || strings.Contains(lowerBody, "jinja2") || strings.Contains(lowerBody, "express(") {
			addTag("web")
		}
		if strings.Contains(lowerBody, "z3") {
			addTag("z3")
		}
	}

	if strings.Contains(lowerName, "pwn") {
		addTag("pwn")
	}
	if strings.Contains(lowerName, "crypto") || strings.Contains(lowerName, "rsa") {
		addTag("crypto")
	}
	if strings.Contains(lowerName, "rev") || strings.Contains(lowerName, "crack") {
		addTag("reverse")
	}

	for tag := range tagSet {
		pf.Tags = append(pf.Tags, tag)
	}
	sort.Strings(pf.Tags)
	return pf
}

func inferCategory(configured string, files []PrecheckFile, tags []string, targets []string) string {
	cfg := strings.ToLower(strings.TrimSpace(configured))
	if cfg != "" && cfg != "auto" {
		return cfg
	}
	tagSet := map[string]bool{}
	for _, t := range tags {
		tagSet[t] = true
	}
	if tagSet["pwn"] || (tagSet["elf"] && (tagSet["libc_provided"] || len(targets) > 0)) {
		return "pwn"
	}
	if tagSet["elf"] || tagSet["pe"] || tagSet["reverse"] {
		return "reverse"
	}
	if tagSet["crypto"] || tagSet["rsa"] {
		return "crypto"
	}
	if tagSet["pcap"] || tagSet["zip"] || tagSet["image"] {
		return "misc"
	}
	if tagSet["web"] || len(targets) > 0 {
		for _, tg := range targets {
			if strings.HasPrefix(tg, "http://") || strings.HasPrefix(tg, "https://") {
				return "web"
			}
		}
	}
	if len(files) > 0 && files[0].Kind == "script" {
		return "crypto"
	}
	return "auto"
}

func isPlaceholderCandidateFileName(name string) bool {
	l := strings.ToLower(strings.TrimSpace(filepath.ToSlash(name)))
	base := strings.ToLower(filepath.Base(l))
	if strings.HasSuffix(base, ".md") || strings.HasSuffix(base, ".markdown") {
		return true
	}
	for _, needle := range []string{
		"readme", "dummy", "example", "sample", "dockerfile", "docker-compose",
		"flag.sh", "run.sh", "start.sh", "entrypoint.sh", "fake_flag", "test_flag",
	} {
		if strings.Contains(base, needle) || strings.Contains(l, "/"+needle) {
			return true
		}
	}
	return false
}

func extractAttachmentPlaceholderFlags(a artifacts.Artifact, diskPath string) []string {
	const maxRead = 256 << 10
	seen := map[string]bool{}
	var out []string
	collect := func(buf []byte) {
		if len(buf) == 0 {
			return
		}
		for _, fl := range ExtractFlags(string(buf), 16) {
			k := strings.ToLower(fl)
			if !seen[k] {
				seen[k] = true
				out = append(out, fl)
			}
		}
	}
	if zr, err := zip.OpenReader(diskPath); err == nil {
		defer zr.Close()
		scanned := 0
		for _, f := range zr.File {
			if f.FileInfo().IsDir() || f.Flags&0x1 != 0 || scanned >= 64 || f.UncompressedSize64 > 2<<20 {
				continue
			}
			if !isPlaceholderCandidateFileName(f.Name) {
				continue
			}
			scanned++
			if rc, oerr := f.Open(); oerr == nil {
				buf, _ := io.ReadAll(io.LimitReader(rc, maxRead))
				_ = rc.Close()
				collect(buf)
			}
		}
		return out
	}
	if isPlaceholderCandidateFileName(a.Name) && a.Size <= 2<<20 {
		if f, err := os.Open(diskPath); err == nil {
			buf, _ := io.ReadAll(io.LimitReader(f, maxRead))
			_ = f.Close()
			collect(buf)
		}
	}
	return out
}

// RunPrecheck runs deterministic zero-LLM Phase-0 inspection on taskID's attachments
// and target description, matches historical Tips, persists precheck_result, and
// writes an L1/L2/L3 diagnostic Fact onto the shared Board.
func (s *Service) RunPrecheck(ctx context.Context, taskID int64, force bool) (*PrecheckResult, error) {
	if s == nil || s.DB == nil || taskID <= 0 {
		return nil, fmt.Errorf("invalid ctf service or task id")
	}
	taskRow, err := s.DB.GetTask(taskID)
	if err != nil {
		return nil, err
	}
	if taskRow == nil || !db.IsSandboxTaskMode(taskRow.Mode) {
		return nil, fmt.Errorf("CTF/AD sandbox task %d not found", taskID)
	}
	store := artifacts.Store{Root: s.Root}
	m, err := store.Inputs(taskID, 0)
	if err != nil {
		return nil, err
	}
	fpRaw, _ := json.Marshal(struct {
		Hash string `json:"hash"`
		Name string `json:"name"`
		Desc string `json:"desc"`
		Goal string `json:"goal"`
		Chal string `json:"chal"`
	}{Hash: Hash(m), Name: taskRow.Name, Desc: taskRow.Description, Goal: taskRow.Goal, Chal: taskRow.ChallengeType})
	fpHash := SHA(fpRaw)

	if !force {
		if existingRaw, err := s.DB.TaskPrecheck(ctx, taskID); err == nil && len(existingRaw) > 0 {
			var cached PrecheckResult
			if json.Unmarshal(existingRaw, &cached) == nil && cached.InputHash == fpHash {
				return &cached, nil
			}
		}
	}

	targets := extractTargets(taskRow.Description, taskRow.Goal)
	files := make([]PrecheckFile, 0, len(m.Files))
	tagSet := map[string]bool{}
	baselineSeen := map[string]bool{}
	var baselineFlags []string
	for _, a := range m.Files {
		diskPath, perr := store.InputPath(taskID, a)
		if perr != nil {
			continue
		}
		pf := inspectArtifactFile(a, diskPath)
		files = append(files, pf)
		for _, tg := range pf.Tags {
			tagSet[tg] = true
		}
		// Only record attachment plaintext placeholder flags when the challenge has a remote target,
		// so pure static offline challenges whose real flag sits in attachments are never filtered.
		if len(targets) > 0 {
			for _, fl := range extractAttachmentPlaceholderFlags(a, diskPath) {
				k := strings.ToLower(fl)
				if !baselineSeen[k] {
					baselineSeen[k] = true
					baselineFlags = append(baselineFlags, fl)
				}
			}
		}
	}
	sort.Strings(baselineFlags)
	if taskRow.ChallengeType != "" && taskRow.ChallengeType != "auto" {
		tagSet[strings.ToLower(taskRow.ChallengeType)] = true
	}
	for _, tg := range extractTextTags(taskRow.Name, taskRow.Description, taskRow.Goal) {
		tagSet[tg] = true
	}
	tags := make([]string, 0, len(tagSet))
	for t := range tagSet {
		tags = append(tags, t)
	}
	sort.Strings(tags)

	inferred := inferCategory(taskRow.ChallengeType, files, tags, targets)
	tips, _ := s.DB.SearchTips(ctx, inferred, tags, 5)
	for _, tip := range tips {
		_ = s.DB.RecordTaskTipHit(ctx, taskID, tip.ID)
	}

	var sumParts []string
	sumParts = append(sumParts, fmt.Sprintf("type=%s (inferred=%s)", taskRow.ChallengeType, inferred))
	sumParts = append(sumParts, fmt.Sprintf("files=%d", len(files)))
	if len(targets) > 0 {
		sumParts = append(sumParts, "[LIVE TARGET PRESENT: "+strings.Join(targets, ",")+"]")
	}
	if len(tags) > 0 {
		sumParts = append(sumParts, "tags=["+strings.Join(tags, ",")+"]")
	}
	if len(tips) > 0 {
		sumParts = append(sumParts, fmt.Sprintf("tips=%d", len(tips)))
	}

	res := &PrecheckResult{
		TaskID:                   taskID,
		InputHash:                fpHash,
		ChallengeType:            taskRow.ChallengeType,
		InferredCategory:         inferred,
		Targets:                  targets,
		Tags:                     tags,
		Files:                    files,
		MatchedTips:              tips,
		BaselinePlaceholderFlags: baselineFlags,
		Summary:                  strings.Join(sumParts, " | "),
		GeneratedAt:              time.Now().UTC(),
	}
	raw, err := json.Marshal(res)
	if err != nil {
		return nil, err
	}
	if err := s.DB.SaveTaskPrecheck(ctx, taskID, raw); err != nil {
		return nil, err
	}
	_, _ = s.DB.UpsertBoardItemByTitle(ctx, db.BoardItem{
		TaskID:   taskID,
		Kind:     db.BoardKindFact,
		Title:    "Phase-0 Precheck 化验单",
		Summary:  res.Summary,
		Detail:   string(raw),
		Verified: true,
	})
	return res, nil
}
