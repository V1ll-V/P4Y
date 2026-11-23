package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"p3y/db"
	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/harness"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/Autumn-27/norma/transcript"
)

type (
	ctfHelperRunnerKey struct{}
	ctfHelperSubKey    struct{}
)

// CTFHelperRequest configures a short, disposable Helper sidecar run over the shared
// CTF workspace so noisy static analysis / brute-force / log parsing stays out of
// Solver's primary context window.
type CTFHelperRequest struct {
	Name        string             `json:"name,omitempty"`
	Goal        string             `json:"goal"`
	FocusPath   string             `json:"focus_path,omitempty"`
	SaveKitName string             `json:"save_kit_name,omitempty"`
	MaxTurns    int                `json:"max_turns,omitempty"`
	Tasks       []CTFHelperRequest `json:"tasks,omitempty"`
}

// CTFHelperResult holds the condensed deliverable returned by Helper back to Solver.
type CTFHelperResult struct {
	Name           string `json:"name,omitempty"`
	Goal           string `json:"goal,omitempty"`
	Summary        string `json:"summary"`
	FocusPath      string `json:"focus_path,omitempty"`
	SaveKitName    string `json:"save_kit_name,omitempty"`
	FactsRecorded  int    `json:"facts_recorded"`
	TerminalReason string `json:"terminal_reason,omitempty"`
	Error          string `json:"error,omitempty"`
}

// CTFHelperBatchResult aggregates results when ask_helper fans out multiple concurrent sub-tasks.
type CTFHelperBatchResult struct {
	Mode    string            `json:"mode"`
	Count   int               `json:"count"`
	Results []CTFHelperResult `json:"results"`
}

// CTFHelperRunner executes an ephemeral bounded Helper session.
type CTFHelperRunner func(ctx context.Context, req CTFHelperRequest) (CTFHelperResult, error)

// WithCTFHelperRunner attaches a Helper runner to ctx for Solver's ask_helper tool.
func WithCTFHelperRunner(ctx context.Context, fn CTFHelperRunner) context.Context {
	if fn == nil {
		return ctx
	}
	return context.WithValue(ctx, ctfHelperRunnerKey{}, fn)
}

func ctfHelperRunnerFromContext(ctx context.Context) CTFHelperRunner {
	if ctx == nil {
		return nil
	}
	fn, _ := ctx.Value(ctfHelperRunnerKey{}).(CTFHelperRunner)
	return fn
}

func isCTFHelperContext(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	v, _ := ctx.Value(ctfHelperSubKey{}).(bool)
	return v
}

const ctfHelperSystem = `【思考与输出语言规范】思考与汇报必须全程使用简体中文（命令、代码、路径与专有英文术语除外）。

你是主攻手（Solver）临时召集的短生命周期帮手（Helper），只负责完成当前指派的单一局部脏活（如：Ghidra/radare2 反编译拆解、海量字符串/符号抽取、编写辅助交互脚手架或解析脚本、大体积流量/文件分析），并在完成后立刻销毁独立会话。
1. 仅使用容器内 /work 工具执行；尽量减少冗余回显。
2. 若产出了对主攻手可复用的代码/符号清单，且指派要求沉淀套件，可调用 board_save_kit 保存；若发现关键客观结论，可调用 record_fact 记录精简事实。
3. 严禁替主攻手创建存档点（Savepoint）、回滚或提交 Flag；完成后用结构化中文直接总结关键偏移、接口与已落盘文件，控制在 1200 字以内。`

func stripHelperTools(tools []actool.CoreTool) []actool.CoreTool {
	out := make([]actool.CoreTool, 0, len(tools))
	for _, t := range tools {
		switch t.Name() {
		case "ask_helper", "plateau_fork",
			"board_mark_savepoint", "board_rewind",
			"ctf_submit_flag", "ctf_submit_exploit_proof":
			continue
		}
		out = append(out, t)
	}
	return out
}

func askHelperTool() actool.CoreTool {
	return writeTool("ask_helper", "派出 1 个或多个（最多 3 路并发）短生命周期、独立上下文的 Helper 子代理处理局部脏活（如并行审计多目录源码、同时反编译多个函数、流量/字典解析或脚手架生成），只带回浓缩结论而不污染 Lead-Solver 主上下文。单任务传 goal；并行多任务传 tasks 数组。", obj(map[string]any{
		"goal":          str("单任务模式：交给 Helper 的明确目标（如 '使用 ctf_decompile 分析 /work/chall 的 menu/alloc/free 逻辑并把偏移汇总为 symbols.json'）"),
		"focus_path":    str("可选焦点文件或目录路径（默认 /work）"),
		"save_kit_name": str("可选要求 Helper 完成后调用 board_save_kit 沉淀的套件文件名（如 'symbols.json'、'interact.py'）"),
		"max_turns":     intp("Helper 最大轮数预算（范围 2~12，默认 8）"),
		"tasks": map[string]any{
			"type":        "array",
			"description": "并发子代理模式（最多 3 个互不依赖的并行子任务，如同时审计 Web 后端源码 + 检查前端路由 + 分析配置文件）",
			"items": obj(map[string]any{
				"name":          str("子任务简短标签（如 'audit_auth'、'decompile_vm'）"),
				"goal":          str("该子代理的明确目标"),
				"focus_path":    str("可选焦点路径"),
				"save_kit_name": str("可选沉淀套件文件名"),
				"max_turns":     intp("该子代理轮数上限（2~12，默认 8）"),
			}, "goal"),
		},
	}), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
		if isCTFHelperContext(ctx) {
			return actool.Errorf("Helper 不能嵌套调用 ask_helper"), nil
		}
		runner := ctfHelperRunnerFromContext(ctx)
		if runner == nil {
			return actool.Errorf("当前运行上下文未挂载 Helper 调度器"), nil
		}
		var req CTFHelperRequest
		if err := json.Unmarshal(in, &req); err != nil {
			return actool.Errorf(fmt.Sprintf("参数解析失败: %v", err)), nil
		}
		if len(req.Tasks) > 0 {
			const maxParallelHelpers = 3
			tasks := make([]CTFHelperRequest, 0, min(len(req.Tasks), maxParallelHelpers))
			for i, sub := range req.Tasks {
				if len(tasks) >= maxParallelHelpers {
					break
				}
				sub.Goal = strings.TrimSpace(sub.Goal)
				if sub.Goal == "" {
					continue
				}
				if strings.TrimSpace(sub.Name) == "" {
					sub.Name = fmt.Sprintf("sub#%d", i+1)
				}
				if sub.FocusPath == "" {
					sub.FocusPath = req.FocusPath
				}
				if sub.MaxTurns == 0 {
					sub.MaxTurns = req.MaxTurns
				}
				tasks = append(tasks, sub)
			}
			if len(tasks) == 0 {
				return actool.Errorf("tasks 中至少需要 1 个非空 goal"), nil
			}
			results := make([]CTFHelperResult, len(tasks))
			var wg sync.WaitGroup
			for i, sub := range tasks {
				wg.Add(1)
				go func(idx int, item CTFHelperRequest) {
					defer wg.Done()
					res, err := runner(ctx, item)
					if err != nil {
						res = CTFHelperResult{Name: item.Name, Goal: item.Goal, Error: err.Error()}
					} else {
						if res.Name == "" {
							res.Name = item.Name
						}
						if res.Goal == "" {
							res.Goal = item.Goal
						}
					}
					results[idx] = res
				}(i, sub)
			}
			wg.Wait()
			b, _ := json.Marshal(CTFHelperBatchResult{
				Mode:    "parallel",
				Count:   len(results),
				Results: results,
			})
			return actool.Text(string(b)), nil
		}
		req.Goal = strings.TrimSpace(req.Goal)
		if req.Goal == "" {
			return actool.Errorf("goal 或 tasks 不能为空"), nil
		}
		res, err := runner(ctx, req)
		if err != nil {
			return actool.Errorf(fmt.Sprintf("Helper 执行失败: %v", err)), nil
		}
		b, _ := json.Marshal(res)
		return actool.Text(string(b)), nil
	})
}

func (w *Worker) runCTFHelper(ctx context.Context, as *db.AssetStore, ts *db.ExplorationStore, taskID, intentID int64, runDir string, emit func(db.Activity), req CTFHelperRequest) (CTFHelperResult, error) {
	if w == nil || w.prov == nil {
		return CTFHelperResult{}, fmt.Errorf("未配置模型 Provider")
	}
	turns := req.MaxTurns
	if turns <= 0 {
		turns = 8
	}
	if turns < 2 {
		turns = 2
	}
	if turns > 12 {
		turns = 12
	}

	tsx := NewToolSet(ts, "helper")
	tsx.SetTaskID(taskID)
	if as != nil {
		tsx.SetAssetStore(as)
	}
	tsx.SetOwnerNode(intentID)

	base := append(tsx.WorkerTools(), w.extraTools...)
	base = append(base, defaultToolsExcept("MultiEdit", "Glob", "Grep")...)
	subCtx := WithRunInfo(ctx, RunInfo{TaskID: taskID, ExplorationID: explorationID(ts), IntentID: intentID})
	subCtx = WithCTFProxy(subCtx, w.proxyAddr, w.proxyCACert)
	subCtx = context.WithValue(subCtx, ctfHelperSubKey{}, true)
	subCtx = transcript.WithSessionID(subCtx, fmt.Sprintf("exp%d-helper-i%d", explorationID(ts), intentID))
	subCtx, base = ctfBase(subCtx, w.workDir, ts, taskID, intentID, base)
	tools, def, cleanup := AugmentTools(subCtx, "worker", base)
	defer cleanup()
	tools = stripHelperTools(tools)

	system, boundary := deferredSystem(ctfHelperSystem, def)
	var prompt strings.Builder
	fmt.Fprintf(&prompt, "【Helper 子任务】\n目标：%s\n工作目录：/work（与主攻手共享同一容器工作区，原始附件只读位于 /work/.inputs）\n", req.Goal)
	if strings.TrimSpace(req.FocusPath) != "" {
		fmt.Fprintf(&prompt, "重点关注路径：%s\n", strings.TrimSpace(req.FocusPath))
	}
	if strings.TrimSpace(req.SaveKitName) != "" {
		fmt.Fprintf(&prompt, "完成后若产物有效，请调用 board_save_kit(name=%q) 沉淀。\n", strings.TrimSpace(req.SaveKitName))
	}
	if ts != nil && ts.Database() != nil {
		if idx := ts.Database().RenderBoardIndex(subCtx, taskID); idx != "" {
			prompt.WriteString(idx)
		}
	}
	prompt.WriteString("\n请直接在预算内完成并在最后一次回复输出精简结论。")

	helperTimeout := 120 * time.Second
	if dl, ok := subCtx.Deadline(); ok {
		if rem := time.Until(dl); rem > 0 && rem < helperTimeout {
			helperTimeout = rem
		}
	}

	opts := agentcore.Options{
		Provider:              withRoleThinking(w.prov, "helper", "worker", true),
		SystemPrompt:          system,
		DynamicBoundary:       boundary,
		Tools:                 tools,
		DeferredTools:         def.Deferred,
		UnlockSet:             def.Unlock,
		PermissionMode:        permission.ModeBypass,
		EnableWebFetch:        false,
		WebFetchProxy:         w.proxyAddr,
		WebFetchCACert:        w.proxyCACert,
		BashEnv:               proxyEnv(w.proxyAddr, w.proxyCACert),
		WorkingDir:            runDir,
		MaxTurns:              turns,
		MaxDuration:           helperTimeout,
		ToolOutputDir:         cmdOutDir(runDir),
		Compaction:            compactionConfig(w.compactionWindow()),
		NonStreaming:          w.nonStreaming(),
		MaxTokens:             w.maxTokens(),
		Settlement:            &harness.Settlement{Prompt: "已达轮次上限，请立刻停止调用执行工具并直接输出你的浓缩结论给 Solver。", MaxTurns: 1, DisabledTools: ctfExecutionTools},
	}

	helperEmit := func(r db.Activity) {
		if emit != nil {
			iid := intentID
			r.NodeID, r.Worker = &iid, "helper"
			emit(r)
		}
	}
	helperEmit(db.Activity{Kind: "helper_start", Summary: fmt.Sprintf("Helper 子任务启动：%s", truncOutput(req.Goal, 140))})
	text, reason, err := captureRun(subCtx, opts, prompt.String(), helperEmit)
	res := CTFHelperResult{
		Summary:        strings.TrimSpace(text),
		FocusPath:      strings.TrimSpace(req.FocusPath),
		SaveKitName:    strings.TrimSpace(req.SaveKitName),
		FactsRecorded:  tsx.Writes().Facts,
		TerminalReason: string(reason),
	}
	if err != nil {
		res.Error = err.Error()
	}
	if res.Summary == "" && res.Error == "" {
		res.Summary = "Helper 已执行完成，但未返回文本摘要。"
	}
	helperEmit(db.Activity{Kind: "helper_done", Summary: fmt.Sprintf("Helper 完成（reason=%s, facts=%d）", reason, res.FactsRecorded), Detail: truncOutput(res.Summary, 600)})
	return res, nil
}
