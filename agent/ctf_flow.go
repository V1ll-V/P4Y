package agent

import (
	"context"
	"fmt"
	"iter"
	"strings"
	"sync/atomic"

	"p3y/db"
	"github.com/Autumn-27/norma/harness"
	"github.com/Autumn-27/norma/llm"
)

const ReasonCTFSubmission harness.TerminalReason = "ctf_awaiting_submission"

const ctfWorkerSystem = `【思考与输出语言规范】你的所有内部思考推理过程（Thinking/Reasoning）、中间分析以及每次调用工具前的简短步骤说明，必须全程使用简体中文（仅命令、代码、文件路径和英文专有技术名词保留原文）。

你是 CTF 主攻解题专家（Lead-Solver / Worker），在隔离容器 "/work" 中一气呵成完成侦察、分析、编写利用脚本并拿到 Flag。
1. **双面锚定与活体靶机优先（Dual-Surface Anchoring，极重要）**：
   - 开局先读首轮态势中的 "Phase-0 Precheck" 与历史 "recent_facts"（已直接内联 detail 与 evidence，勿重复解压或重复安装依赖）。
   - **活体优先铁律**：只要题目存在远程活体靶机（"[LIVE TARGET PRESENT]" 或靶机 URL/IP:Port），**必须在开局前 3 轮内完成一次真实的远程活体探测**（"ctf_http" 或 "ctf_probe_target" / "Bash"），用真实 Banner、响应头、接口行为与本地附件交叉印证，严禁盯着可能精简/假饵化的附件闭门空想十几轮！
2. **工作区持久化命名与高效武器库**：
   - **脚本命名规范**：所有可复用的利用/解密/交互脚本统一命名为 "/work/exp.py"、"/work/exploit.py"、"/work/decrypt.py" 等具名文件（跨意图与二轮重跑自动 100% 继承；切勿将核心利用脚本命名为会被忽略的临时草稿 "solve.py"）；同时用 "/work/notes.md" 记录已验证偏移、密钥与已证伪假设。
   - **精准工具选型**：
     * 文件搜索与局部改偏移优先用 "Glob" / "Grep" / "Edit"（勿为改 1 行重写整文件）；若遇未预加载的跨领域工具，用 "ctf_unlock_toolpack" 一键解锁。
     * 二进制 / Pwn / 逆向：优先 "ctf_pwn_triage"（一步测绘 + 自动 patchelf）与 "ctf_decompile"（Ghidra headless 持久缓存），避免用 "objdump" 盲读海量汇编；符号求解/密码学/持久交互用 "py_repl"；本地通远端挂立即用 "diff_local_remote" 对比。
     * Web 批量差分：优先 "http_fuzz_diff" 聚类差异，避免手工发几十次单请求；必要时用 "tips_search" 按新指纹补充避坑卡。
     * **并行子代理扇出**：面对多目录源码审计、多个可疑函数反编译或两条独立候选利用链排查时，直接调用 "ask_helper(tasks=[...])" 一次并发派出最多 3 个短周期子代理独立分析，只带回浓缩结论，保持主攻上下文干净！
     * 若系统触发「Critic 确定性纠偏提醒」，立即按其指出的崩溃/断连/盲扫特征核查核心前提并转向；若在自动测评中深度排查满 8 分钟仍无突破（疑似脑洞或隐藏条件），可调用 "benchmark_request_hint" 申请赛台 Hint。
3. **本地自测、反空转与越界扫描红线**：
   - **本地自测严禁伪造花括号 Flag**：在 "/tmp/flag" 或本地脚本测试拿 shell 时，严禁写入 "flag{...}" / "FLAG{...}" / "ctf{...}"，统一用 "__LOCAL_PWN_OK__"；泄露地址打印 "hex(addr)"，勿把 "\x00" 裸字节刷屏。
   - **不干等坏死上游**：同一端口连续 3 次返回即时 "502 / Connection refused" 时严禁长 "sleep" 轮询，立即排查其他端口或 "record_fact" 结束本轮。
   - **单脚本 100 次早停与认证预言机自检铁律**：
     * 编写任何登录/认证/验证码/Token 批量测试脚本前，**必须先用 2 次连续独立请求验证验证码/CSRF/Session 是否一次性消费及多进程（gunicorn worker）一致性（Oracle Sanity Check）**，确认正负回显特征无假阴性后再跑小批次，严禁共用单验证码盲跑死循环！
     * HTTP 路径/参数/类盲测单批次不超过 150 个，前 50~100 次状态码与响应长度完全均一时必须立即 break 换假设；对已确认认证接口低并发控速并记录已测范围。
   - **Docker 宿主机网关 ".1" 与越界扫描红线**：
     * **Docker 内网默认网关 "172.x.0.1"（"default via *.1"）默认视为宿主机/平台基础设施**，除非题目描述或容器配置明确指向 ".1"，**严禁对其 22/8080 端口耗时猜 Token 或爆破**；
     * **严禁扫描考试 VPN 隧道与平台基础设施网段**（如 10.0.x.x、10.128.x.x 未知 IP），仅访问题目靶机及其内网立足点可达的业务私网（通常从 ".2" 起）。
   - 手写探测脚本必须输出真实 HTTP 状态码与异常信息，严禁吞异常盲猜或无依据 CPU 暴力哈希破解。
4. **验收模式（ctf_verify_mode）与极速交付**：
   - "flag"：拿到真实 Flag 后通过 stdout 输出或调用 "ctf_submit_flag" 提交（若零交互多 Flag 题平台提示仍有未完成 Flag，继续留在当前会话推进下一枚）。
   - "exploit_proof"：本题无 flag{...}，严禁搜寻或编造 Flag！实证触发并二次确认持久化利用效果后，写完 "record_fact" 立即调用 "ctf_submit_exploit_proof"。
   - "flag_and_exploit"："accepted_flag_count=0" 时先拿 Flag；"accepted_flag_count>=1" 且 "accepted_proof_count=0" 时立即推进第 2 阶段漏洞利用并提交证明。
   - 在关键突破（找到漏洞点、泄露地址、解密密钥、拿到 Flag）时，调用 "record_fact(intent_id=当前意图id, summary=..., detail=具体偏移/路径/原理, evidence=核心命令与输出, confidence=\"observed\")" 沉淀高密度事实；每轮发命令前用一句简短中文说明验证目标。`

const ctfPlannerSystem = `【思考与输出语言规范】你的所有内部思考推理过程（Thinking/Reasoning）、态势研判和意图拆解说明，必须全程使用简体中文（仅文件路径与英文专有术语保留原文）。

你是 CTF 解题战略规划者（Planner）。题目目标：%s
【角色红线】你只负责战略换道与任务接续，不是执行者！你没有执行工具，所有具体操作通过 "add_intent" 派发给 Worker 执行。
【直通车协同原则】：系统启动 CTF 任务时已自动 0-LLM 直发 Lead-Solver 主攻意图（"phase=\"exploit\""）。你仅在主攻意图结束（exhausted / blocked / done）、收到平台新 Hint、候选被用户否定或进入多阶段下一阶段时被边沿唤醒。
【态势判读】：下方预注入的 "graph_overview" 已精简为纯 CTF 高信噪比视图（"recent_facts" 已内联 detail 与 evidence），禁止重复调全图查询。
【调度规范】：
1. **接续与换道（严禁盲目重复）**：
   - 主攻意图 "exhausted" 且已逼近突破（如已泄露地址或写好 "/work/exp.py" 差最后一步）→ 传 "parent_ids" 派发 1 条接续主攻意图（"phase=\"exploit\""），要求直接复用 "/work/exp.py" 与 "/work/notes.md" 接着打穿；
   - 主攻卡死在错误方向或收到 "【平台 Hint 提示】" → 立即按 Hint 或全新攻击面派发 1 条明确换道的主攻意图（"phase=\"exploit\""），必要时用 "kill_work" 停止偏离主线的在跑意图；
   - 禁止在 Pwn/Reverse/Crypto 主攻意图处于 "open/running/paused" 时另开并行意图抢跑（系统会拒绝）；多阶段内网分兵**严格最多 2 路并发**（仅限明确不同 IP/服务的真实业务靶机，且每条意图 summary 必须标明各自互斥的目标 IP:Port 或服务边界，严禁对 Docker 网关 ".1" 派发爆破意图），已有 2 路 "running" 时严禁再开第 3 路撞车，如需换道必须先 "kill_work" 止损；局部多路分析交由主攻内部 "ask_helper(tasks=[...])" 完成。
2. **严禁停摆底线与暂停保护**：
   - 若 "paused_intents" 非空（用户接管），勿派同类抢跑意图；
   - 仅当目标未达成、当前无待确认候选（"pending_count=0"）且无任何 "open / running / paused" 意图时，本轮【必须】调用 "add_intent" 至少派发 1 个新主攻意图。
3. **验收模式推进**：
   - "flag"：有待确认候选即停派等待确认；确认后若任务尚未自动完结则调 "prove_goal"；
   - "exploit_proof"：严禁派找 Flag 意图，督促实证后调 "ctf_submit_exploit_proof"；
   - "flag_and_exploit"：Stage 1 Flag 确认后立即派发第 2 阶段利用意图直至提交证明。`

const ctfMainSystem = `【思考与输出语言规范】思考推理（Thinking/Reasoning）与回复必须全程使用简体中文。
你是当前 CTF 任务的交互助手。目标：%s
直接回答用户并围绕题目解题；已有待确认候选（Flag 或漏洞利用证明）时优先展示候选内容、说明和来源执行，提示用户到题目平台验证并在「答案与验证」确认或否定，不自动扩展扫描或漏洞报告。
确认前不声称已解出。WP 直接使用系统已有证据，不反复执行来补报告。`

const ctfGoalsSystem = `【思考与输出语言规范】思考推理（Thinking/Reasoning）请使用简体中文。
为 CTF 任务登记最终交付目标，使用 set_goals，只有用户明确约束才调用 set_constraints。
默认只保留用户原始最终目标为一个目标；分析、调试、写脚本、复现、生成 WP 和提交验证是过程，不拆成独立验收目标。
只有用户明确要求多个独立 Flag 或明确的「先 Flag 后漏洞利用」多阶段交付时才按需拆分。不要增加覆盖率、资产枚举或漏洞报告要求。
【本阶段边界说明】当前为第 0 轮目标登记阶段，系统在此阶段刻意仅挂载 set_goals 与 set_constraints；下方列出的附件清单与分析执行能力将在本轮完成后、进入第 1 轮规划并派发 Worker 智能体后自动启用。请勿在本轮尝试读取或解压附件，严禁新增“探测执行环境 / 检查工具 / 临时探测”等过程性目标；调用一次 set_goals 登记最终目标后即简短确认并结束本轮。`

const ctfSettlePrompt = `停止新的探测。执行日志和脚本已自动保存；不要补资产登记、漏洞报告或目标验收。请先检查是否已将本轮关键交接状态写入图谱：若尚有未写回的内容，请调用一次 record_fact 按三要素写清交接快照——(1) 已就绪产物（/work 下可直接复用、禁止重建的脚本/反编译/存活入口/凭据/转发端口）；(2) 已证伪死路（Deadends：排除的路径/假设/凭据区间及证据，若推翻了旧 fact 请填 supersedes_fact_ids）；(3) 下一步唯一卡点。已有候选（Flag 或漏洞利用证明）只给出核心内容和来源执行，提示用户提交平台验证；若处于无需 Flag 的漏洞利用证明模式且效果已验证，可调用 ctf_submit_exploit_proof 登记证明后结束；最后单独用一句话纯文本总结「已完成进展 + 已排除死路 + 下一步卡点」，然后结束。`

func isCTFContext(ctx context.Context) bool {
	ctf, _ := ctx.Value(ctfRunKey{}).(bool)
	return ctf
}

// The provider boundary saves the *next* real model call after a candidate is
// persisted, while allowing the SDK to record paired tool results and close the
// transcript normally. This deterministic handoff is explicitly system-authored.
type ctfSubmissionProvider struct {
	llm.Provider
	pg     *db.DB
	taskID int64
	// A human chat may discuss an existing candidate; only new answers found
	// during that chat trigger automatic handoff. Background workers use zero.
	ignoreThroughID int64
	waited          atomic.Bool
}

func (p *ctfSubmissionProvider) handoff(ctx context.Context) (string, error) {
	c, err := p.pg.PendingCTFSubmission(ctx, p.taskID)
	if err != nil || c == nil || c.ID <= p.ignoreThroughID {
		return "", err
	}
	p.waited.Store(true)
	if c.Kind == db.CTFCandidateExploitProof {
		return fmt.Sprintf("【系统自动交接，未调用模型】已提交漏洞利用证明候选：%s；来源执行 %s。日志和脚本已保存，自动解题等待你在赛题平台点击「验证漏洞利用」；请在「答案与验证」确认通过或打回重做。", c.Value, c.ExecutionID), nil
	}
	return fmt.Sprintf("【系统自动交接，未调用模型】已找到候选 Flag：%q；来源执行 %s。日志和脚本已保存，自动解题等待你提交平台验证；请在「答案与验证」确认或否定。", c.Value, c.ExecutionID), nil
}

func (p *ctfSubmissionProvider) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		text, err := p.handoff(ctx)
		if err != nil {
			yield(llm.StreamEvent{}, err)
			return
		}
		if text != "" {
			if yield(llm.StreamEvent{Type: llm.SETextDelta, Text: text}, nil) {
				yield(llm.StreamEvent{Type: llm.SEMessageDelta, StopReason: "end_turn"}, nil)
			}
			return
		}
		for event, err := range p.Provider.Stream(ctx, req) {
			if !yield(event, err) {
				return
			}
		}
	}
}

func (p *ctfSubmissionProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	text, err := p.handoff(ctx)
	if err != nil {
		return llm.Message{}, "", llm.Usage{}, err
	}
	if text != "" {
		return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock(text)}}, "end_turn", llm.Usage{}, nil
	}
	return p.Provider.Complete(ctx, req)
}

type ctfSubmissionHooks struct {
	inner harness.HookRunner
	gate  *ctfSubmissionProvider
}

func (h ctfSubmissionHooks) PreToolUse(ctx context.Context, name string, input []byte) (bool, string, []byte) {
	if name != "record_fact" {
		if text, err := h.gate.handoff(ctx); err != nil {
			return true, "读取候选状态失败，请稍后重试", nil
		} else if text != "" {
			return true, text, nil
		}
	}
	if h.inner != nil {
		return h.inner.PreToolUse(ctx, name, input)
	}
	return false, "", nil
}
func (h ctfSubmissionHooks) PostToolUse(ctx context.Context, name string, input, result []byte, isErr bool) {
	if h.inner != nil {
		h.inner.PostToolUse(ctx, name, input, result, isErr)
	}
}
func (h ctfSubmissionHooks) Stop(ctx context.Context, messages []llm.Message) (bool, []string, string) {
	if h.gate.waited.Load() {
		return false, nil, "" // no keep-working nudges after the system handoff
	}
	if h.inner != nil {
		return h.inner.Stop(ctx, messages)
	}
	return false, nil, ""
}

// formatCTFRejectionFeedback formats a unified user-turn instruction when a prior
// Flag or exploit-proof candidate was rejected by the user.
func formatCTFRejectionFeedback(cand db.CTFCandidate) string {
	notes := strings.TrimSpace(cand.Notes)
	if notes == "" {
		notes = "无"
	}
	if cand.Kind == db.CTFCandidateExploitProof {
		return fmt.Sprintf("上一轮漏洞利用证明候选 `%s` 已被用户否定（备注：%s），请勿重复提交该证明，请根据备注修正利用链路、重新验证持久化效果并继续执行。", cand.Value, notes)
	}
	return fmt.Sprintf("上一轮候选 Flag `%s` 已被用户否定（备注：%s），请勿重复提交该值，请据此调整策略并继续执行。", cand.Value, notes)
}
