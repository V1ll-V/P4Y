package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"p3y/db"
	"github.com/Autumn-27/norma/harness"
	"github.com/Autumn-27/norma/llm"
)

// ctfTargetScopeGuard enforces application-layer target boundary governance for
// multi-challenge shared-VPN benchmark sessions without mutating the shared
// kernel network namespace (which would break concurrent tasks sharing a VPN).
//
// Two deterministic tiers:
//   - Level 1 (absolute blocklist): entry IPv4s belonging to OTHER challenges
//     in the same benchmark session.
//   - Level 2 (shared entry /24 guard): other unknown IPv4s inside the same
//     RFC1918 /24 subnet as this task's explicit entry IP(s), unless the task's
//     own description explicitly lists that CIDR as a scan range.
//
// Non-benchmark tasks (manual pentest / open-range CTF) have nil guard (no-op).
type ctfTargetScopeGuard struct {
	allowedIPs       map[string]bool
	siblingIPs       map[string]bool
	protectedSlash24 map[string]bool // "a.b.c." prefix
	allowedList      []string
	protectedCIDRs   []string // "a.b.c.0/24"
}

var (
	scopeIPv4Re = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b`)
	scopeCIDRRe = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)/(?:[1-9]|[12]\d|3[0-2])\b`)
)

func ipv4Slash24Prefix(ipStr string) (prefix string, cidr string, private bool) {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return "", "", false
	}
	v4 := ip.To4()
	if v4 == nil {
		return "", "", false
	}
	// Only guard RFC1918 private shared-platform ranges (10/8, 172.16/12, 192.168/16).
	isPriv := v4[0] == 10 || (v4[0] == 172 && v4[1] >= 16 && v4[1] <= 31) || (v4[0] == 192 && v4[1] == 168)
	if !isPriv {
		return "", "", false
	}
	p := fmt.Sprintf("%d.%d.%d.", v4[0], v4[1], v4[2])
	return p, p + "0/24", true
}

func newCTFTargetScopeGuard(allowedIPs, siblingIPs, explicitCIDRs []string) *ctfTargetScopeGuard {
	if len(allowedIPs) == 0 && len(siblingIPs) == 0 {
		return nil
	}
	var explicitNets []*net.IPNet
	for _, c := range explicitCIDRs {
		if _, n, err := net.ParseCIDR(strings.TrimSpace(c)); err == nil && n != nil {
			explicitNets = append(explicitNets, n)
		}
	}
	g := &ctfTargetScopeGuard{
		allowedIPs:       make(map[string]bool, len(allowedIPs)),
		siblingIPs:       make(map[string]bool, len(siblingIPs)),
		protectedSlash24: make(map[string]bool),
	}
	cidrSeen := map[string]bool{}
	for _, raw := range allowedIPs {
		ip := net.ParseIP(strings.TrimSpace(raw))
		if ip == nil || ip.To4() == nil {
			continue
		}
		v4 := ip.To4()
		s := v4.String()
		if !g.allowedIPs[s] {
			g.allowedIPs[s] = true
			g.allowedList = append(g.allowedList, s)
		}
		// Skip Level 2 /24 guard if the challenge description explicitly requested scanning this CIDR.
		inExplicitCIDR := false
		for _, en := range explicitNets {
			if en.Contains(v4) {
				inExplicitCIDR = true
				break
			}
		}
		if !inExplicitCIDR {
			if p, cidr, priv := ipv4Slash24Prefix(s); priv && !cidrSeen[cidr] {
				cidrSeen[cidr] = true
				g.protectedSlash24[p] = true
				g.protectedCIDRs = append(g.protectedCIDRs, cidr)
			}
		}
	}
	for _, raw := range siblingIPs {
		ip := net.ParseIP(strings.TrimSpace(raw))
		if ip == nil || ip.To4() == nil {
			continue
		}
		s := ip.To4().String()
		if !g.allowedIPs[s] {
			g.siblingIPs[s] = true
		}
	}
	sort.Strings(g.allowedList)
	sort.Strings(g.protectedCIDRs)
	if len(g.siblingIPs) == 0 && len(g.protectedSlash24) == 0 {
		return nil
	}
	return g
}

func resolveCTFTargetScopeGuard(ctx context.Context, pg *db.DB, taskID int64) *ctfTargetScopeGuard {
	if pg == nil || taskID <= 0 {
		return nil
	}
	qctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	allowed, siblings, explicitCIDRs, ok := pg.BenchmarkTaskTargetScope(qctx, taskID)
	if !ok {
		return nil
	}
	return newCTFTargetScopeGuard(allowed, siblings, explicitCIDRs)
}

// RenderPromptBlock returns an instantiated network boundary statement injected
// into both Planner and Worker contexts so the model understands the exact
// external entry IP(s) vs shared-platform subnet before dispatching or probing.
func (g *ctfTargetScopeGuard) RenderPromptBlock() string {
	if g == nil || len(g.allowedList) == 0 || len(g.protectedCIDRs) == 0 {
		return ""
	}
	return fmt.Sprintf(
		"\n【本题共享赛台网络边界铁律】本题唯一授权外网入口为 `%s`（同赛台接入网段 `%s` 内的其他 IP 均为平台上其他无关题目实例，系统已开启越界硬拦截，严禁从工具容器外网扫描或访问）；若题干或 Hint 提及内部业务系统/OA/文件服务器/跳板机，它们位于入口机背后隔离内网，必须先突破 `%s` 获得立足点或 SSRF 后再向内网渗透。\n",
		strings.Join(g.allowedList, ", "),
		strings.Join(g.protectedCIDRs, ", "),
		strings.Join(g.allowedList, ", "),
	)
}

func (g *ctfTargetScopeGuard) classifyForbiddenIP(ipStr string) (forbidden bool, level int) {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil || ip.To4() == nil {
		return false, 0
	}
	s := ip.To4().String()
	if g.allowedIPs[s] {
		return false, 0
	}
	if g.siblingIPs[s] {
		return true, 1
	}
	if p, _, priv := ipv4Slash24Prefix(s); priv && g.protectedSlash24[p] {
		return true, 2
	}
	return false, 0
}

func (g *ctfTargetScopeGuard) formatBlockMsg(badTarget string, level int) string {
	allowed := strings.Join(g.allowedList, ", ")
	if allowed == "" {
		allowed = "题干指定靶机"
	}
	if level == 1 {
		return fmt.Sprintf("【共享赛台越界硬拦截】目标 `%s` 属于同场测评中另一道无关赛题的实例，严禁访问或扫描！本题唯一授权外网入口为 `%s`；若需探测内部服务/OA/跳板机，必须先突破 `%s` 后从入口机内部渗透。", badTarget, allowed, allowed)
	}
	return fmt.Sprintf("【共享赛台越界硬拦截】目标/网段 `%s` 落在本题入口所在共享赛台接入段（`%s`）内的非本任务地址，严禁从工具容器直接外网扫描或访问！本题唯一授权外网入口为 `%s`，多阶段内网目标请先突破入口机后再内网穿透。", badTarget, strings.Join(g.protectedCIDRs, ", "), allowed)
}

func extractStructuredTargetIPs(raw []byte) []string {
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	collectStr := func(v any) {
		s, ok := v.(string)
		if !ok || strings.TrimSpace(s) == "" {
			return
		}
		for _, ip := range scopeIPv4Re.FindAllString(s, -1) {
			if !seen[ip] {
				seen[ip] = true
				out = append(out, ip)
			}
		}
	}
	for _, key := range []string{"url", "target", "remote_url", "remote_target", "base_url", "host", "endpoint"} {
		if v, exists := m[key]; exists {
			collectStr(v)
		}
	}
	// Also inspect header/body only when explicit proxy/ssrf targets aren't inside allowed host?
	// Keep structured check strictly on destination target fields so legitimate SSRF payloads
	// sent TO the allowed entry target (e.g. targeting internal 172.x) are never misclassified.
	return out
}

func isNonExecutableDocPath(path string) bool {
	ext := strings.ToLower(strings.TrimSpace(filepath.Ext(path)))
	switch ext {
	case ".md", ".txt", ".log", ".json", ".csv", ".html", ".htm", ".xml", ".yaml", ".yml":
		return true
	}
	return false
}

func hasNetworkOrSweepIntent(text string) bool {
	lower := strings.ToLower(text)
	for _, kw := range []string{
		"http://", "https://", "tcp://", "socks5://",
		"curl", "wget", "nmap", "masscan", "nc ", "ncat", "ssh", "sshpass", "telnet", "ftp ",
		"requests.", "urllib", "httpx", "aiohttp", "socket.", ".connect(", "create_connection",
		"ip_network", "ipaddress", "proxy", "sweep", "scan", "brute", "remote(",
	} {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

func stripHashCommentLines(s string) string {
	lines := strings.Split(s, "\n")
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "\n")
}

// CheckToolCall deterministically blocks cross-challenge probing or shared
// entry-subnet sweeping before tool execution. Never blocks read-only local
// tools, documentation writes, or graph write-back tools.
func (g *ctfTargetScopeGuard) CheckToolCall(toolName string, input []byte) (bool, string) {
	if g == nil || len(input) == 0 {
		return false, ""
	}
	switch toolName {
	case "ctf_http", "ctf_probe_target", "http_fuzz_diff", "http_race_probe", "diff_local_remote":
		for _, ip := range extractStructuredTargetIPs(input) {
			if bad, lvl := g.classifyForbiddenIP(ip); bad {
				return true, g.formatBlockMsg(ip, lvl)
			}
		}
		return false, ""

	case "Bash", "ctf_run_background", "py_repl", "Write", "Edit":
		var fields struct {
			Command   string `json:"command"`
			Code      string `json:"code"`
			Content   string `json:"content"`
			NewString string `json:"new_string"`
			FilePath  string `json:"file_path"`
			Path      string `json:"path"`
		}
		if json.Unmarshal(input, &fields) != nil {
			return false, ""
		}
		if toolName == "Write" || toolName == "Edit" {
			targetPath := fields.FilePath
			if targetPath == "" {
				targetPath = fields.Path
			}
			if isNonExecutableDocPath(targetPath) {
				return false, ""
			}
		}
		text := strings.TrimSpace(stripHashCommentLines(strings.Join([]string{fields.Command, fields.Code, fields.Content, fields.NewString}, "\n")))
		if text == "" {
			return false, ""
		}

		// Pattern 1: explicit network CIDR covering any protected shared entry /24
		// (e.g. 10.0.178.0/24 or 10.0.128.0/18). Host interface notation like
		// 10.0.178.80/18 (where IP != network base) is ignored to prevent false blocks.
		for _, cidrStr := range scopeCIDRRe.FindAllString(text, -1) {
			ip, ipnet, err := net.ParseCIDR(cidrStr)
			if err != nil || ipnet == nil || ip == nil {
				continue
			}
			ones, _ := ipnet.Mask.Size()
			if ones >= 32 || !ip.Equal(ipnet.IP) {
				continue
			}
			for allowed := range g.allowedIPs {
				if v4 := net.ParseIP(allowed); v4 != nil && ipnet.Contains(v4) {
					return true, g.formatBlockMsg(cidrStr, 2)
				}
			}
		}

		// Pattern 2: dynamic IP-sweep construction over a protected /24 prefix (e.g. f"10.0.178.{i}", 10.0.178.%d, 10.0.178.$i).
		for prefix := range g.protectedSlash24 {
			for _, pat := range []string{prefix + "{", prefix + "%", prefix + "$", prefix + `"+`, prefix + `" +`, prefix + `'+`, prefix + `' +`} {
				if strings.Contains(text, pat) {
					return true, g.formatBlockMsg(prefix+"0/24", 2)
				}
			}
		}

		// Pattern 3: explicit forbidden IPv4 used in a network/attack context.
		if hasNetworkOrSweepIntent(text) {
			for _, ip := range scopeIPv4Re.FindAllString(text, -1) {
				if bad, lvl := g.classifyForbiddenIP(ip); bad {
					return true, g.formatBlockMsg(ip, lvl)
				}
			}
		}
		return false, ""
	default:
		return false, ""
	}
}

// ctfScopeGuardHooks wraps inner hooks so cross-challenge boundary blocks happen
// BEFORE ctfCriticHooks and never increment Critic's tool-failure counter.
type ctfScopeGuardHooks struct {
	inner harness.HookRunner
	guard *ctfTargetScopeGuard
}

func (h ctfScopeGuardHooks) PreToolUse(ctx context.Context, name string, input []byte) (bool, string, []byte) {
	if h.guard != nil {
		if block, msg := h.guard.CheckToolCall(name, input); block {
			return true, msg, nil
		}
	}
	if h.inner != nil {
		return h.inner.PreToolUse(ctx, name, input)
	}
	return false, "", nil
}

func (h ctfScopeGuardHooks) PostToolUse(ctx context.Context, name string, input, result []byte, isErr bool) {
	if h.inner != nil {
		h.inner.PostToolUse(ctx, name, input, result, isErr)
	}
}

func (h ctfScopeGuardHooks) Stop(ctx context.Context, messages []llm.Message) (bool, []string, string) {
	if h.inner != nil {
		return h.inner.Stop(ctx, messages)
	}
	return false, nil, ""
}
