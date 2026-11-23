# P4Y 项目深度介绍、演进历程与后续开发指南

> 本文档面向 **P4Y** 的核心开发者与后续迭代维护者，系统梳理项目的架构设计、从 **P3Y** 到 **P4Y** 的演进脉络、第一性原理优化思路、核心代码落点、实战观测复盘以及后续开发路线图。

---

## 一、 项目定位与总体架构

**P4Y** 是继承自 **P3Y** 并在第一性原理（First Principles）与 **“Less is More”** 理念指导下完成深度重构的自主安全攻防智能体系统，覆盖四大实战场景：

1. **CTF 自动化解题（Web / Pwn / Reverse / Crypto / Misc）**：支持本地附件静态分析、远程活体靶机探测、动态调试、符号求解、Flag 自动捕获与因果裁剪 Write-up 生成。
2. **多阶段内网纵深渗透**：支持外网打点 → Webshell / 端口转发 / 隧道建立 → 内网横向多主机并发攻坚 → 多 Sub-Flag 递进验收。
3. **多平台零交互自动化测评（Hosted Benchmark）**：原生对接 TSecBench REST、CTF2 / DASCTF MCP、Generic MCP + `Skill.zip`，支持单容器无头托管运行（`< 3GB` 镜像）。
4. **Attack-Defense 实时攻防（AD）**：集成了 `Lead` 态势推演、`Repeater` 0-LLM 并发自动打靶、`Catcher` 流量载荷提取与 `Patcher` 沙箱热修补验证。

### 1.1 双部署形态与系统架构

P4Y 采用“**同核双模式**”设计：同一份 Go 控制面二进制（`cmd/p3y`）既可与外置容器守护进程（`cmd/p3y-box`）配合用于多用户可视化预览/实战，也可通过内置 `LocalBackend`（`P3Y_BOX_LOCAL=1`）与内嵌 PostgreSQL 打包为单容器无头测评镜像（`Dockerfile.bench`）。

```mermaid
flowchart TB
    UI["Web 控制台 (Next.js embedui)<br/>或无头托管入口 (P3Y_HEADLESS=1)"] -->|HTTP / SSE / JWT| CTRL

    subgraph CTRL["控制面 (cmd/p3y)"]
        ENG["弹性调度引擎 (server/engine.go, goals.go)<br/>0-LLM Direct Lead-Solver + Edge Planner"]
        AGENT["智能体层 (agent/)<br/>Lead-Solver / 并发 ask_helper / 0-LLM Critic"]
        BENCH["测评调度器 (server/benchmark.go)<br/>配额管控 / 动量延时 / 受控主动 Hint"]
        POOL["LLM 池与审计 (llmpool / llmrec)<br/>多 Profile Failover + 全量请求落库"]
        PG[("PostgreSQL 16 (db/)<br/>探索图 / 看板 / TipCard / 证据与快照")]
        ENG --> AGENT
        BENCH --> ENG
        AGENT --> POOL
        ENG --> PG
        AGENT --> PG
    end

    CTRL -->|HTTP + Bearer Token<br/>或 LocalBackend 进程内调用| BOX

    subgraph BOX["隔离执行面 (cmd/p3y-box / LocalBackend)"]
        WORK["任务工作区 /work (rw 跨轮继承)<br/>只读附件 /work/.inputs (ro)"]
        EXEC["执行与交互<br/>Bash / PTY / PyREPL / 后台作业 / Savepoint"]
        VPN["共享 VPN Sidecar<br/>p3y-box-vpn-hash (WG / OpenVPN)"]
    end
```

### 1.2 核心代码目录与职责边界

| 目录 | 核心文件 | 职责说明 |
| :--- | :--- | :--- |
| `cmd/p3y` / `cmd/p3y-box` | `main.go` | 控制面服务入口 / 物理隔离容器执行器守护进程入口 |
| `server/` | `engine.go`, `goals.go`, `server.go`, `benchmark.go`, `ctf.go`, `assembly.go` | 任务生命周期、0-LLM 目标与 Lead-Solver 种子化、边沿唤醒 Planner 循环、多平台测评调度、工具目录播种与清理 |
| `agent/` | `worker.go`, `planner.go`, `ctf_flow.go`, `ctf_tools.go`, `helper.go`, `critic.go`, `tools.go`, `toolcatalog.go` | Worker / Planner 执行环、CTF 工具装配与跨界自动预解锁、并发 `ask_helper(tasks[])`、0-LLM 确定性 `Critic`、CTF 图谱去噪与 Fact 内联 |
| `ctf/` | `service.go`, `precheck.go`, `pyrepl.go`, `tips_crystallizer.go`, `wp.go` | 沙箱会话与 `/work` 跨轮继承、`Sync` 缓存、增量脚本快照、Phase-0 Precheck 与双面锚定、TipCard 动态召回与结晶、WP 生成 |
| `ctfrunner/` | `local_engine.go`, `client.go` | Docker 容器与单容器 `LocalBackend` 统一执行接口、PTY/后台作业/硬链接 Savepoint |
| `benchmark/` | `provider.go`, `tsecbench.go`, `mcp.go` | 多赛台协议适配器与 `Skill.zip` 解析 |
| `db/` | `schema.sql`, `exploration.go`, `ctf.go`, `ctf_completion.go`, `tips.go` | PostgreSQL 持久化、探索图读写、只读血缘继承（`SourceTaskIDs`）、CTF 候选与验收事务 |
| `web/` | Next.js 前端工程 | 探索图可视化、任务实时日志、工具管理页、答案与验证、Benchmark 控制台 |

---

## 二、 项目演进历程（从 P3Y 到 P4Y）

### 阶段一：P3Y 奠基期（安全隔离与完整基础设施建设）
P3Y 早期解决了安全智能体最底层的工程可靠性问题：
- **物理隔离**：主服务不挂载 Docker Socket，全部容器操作收敛至 `p3y-box`；采用 Bind-Mount 挂载 `/work` 与只读 `/work/.inputs`。
- **探索图黑板**：将目标（`goal`）、意图（`intent`）、事实（`fact`）、提示（`hint`）持久化到 PostgreSQL，支持冷图折叠与跨任务只读血缘继承（`SourceTaskIDs`）。
- **VPN 与多平台测评**：实现按配置哈希复用的 WireGuard / OpenVPN Sidecar，打通 TSecBench / MCP 零交互批测、环境回收与自动续期。
- **CTF 工具与状态树**：引入 Phase-0 确定性 Precheck、历史 `TipCard` 避坑卡结晶、`Savepoint / Rewind / Deadend` 工作区快照树、`PyREPL` / `http_fuzz_diff` / `diff_local_remote` 神经符号工具。

### 阶段二：P3Y 深化期（动态武库召回与单容器无头托管）
在大量真题批测中，暴露出“开局未知指纹无法召回武库”和“托管评测环境无 Docker-in-Docker”两大痛点，团队完成了两项关键增强：
- **运行中动态二次武库召回（`renderIntentSecondaryTips`）**：在 `agent/task_inputs.go` 与 `ctf/precheck.go` 中实现 `ExtractIntentTags`（内置 `stripNegativeClauses` 剥离括号与排他性否定子句，防止“已排除 SSTI”误触发 SSTI 卡片），Worker 领取下游意图时按新指纹静默补召回 Top-2 未展示过的 `TipCard`，且只读不膨胀命中计数。
- **单容器无头托管镜像（`Dockerfile.bench` + `LocalBackend`）**：将 PostgreSQL 16、全套 CTF 工具链（Ghidra 12.1.4、radare2、pwntools、angr、python-sat、离线 glibc 池）与无头 `cmd/p3y` 集成进单个 `< 1.7 GiB` 压缩包（`p3y-bench-hosted.tar.gz`），实现零同步成本同核双模式。

### 阶段三：P4Y 架构跃迁期（第一性原理 + “Less is More” 深度重构）
在对比业内前沿高分 CTF Agent 架构并对 P3Y 全链路做第一性原理剖析后，我们发现旧版 P3Y 存在 **5 个拖慢解题效率与拉低上限的结构性内耗**：
1. **开局双轮 LLM 空转**：每题启动先跑 `Round-0 Goals LLM` + `Round-1 Planner LLM`，白耗 20~45 秒才发出第 1 条沙箱命令；运行中还有 30 秒周期 `heartbeat` 反复空唤醒 Planner。
2. **三段式割裂失忆**：强制 `Recon(16轮断头台) → 160字截断的 Planner → 全新空白对话 Exploit Worker`，侦察阶段看到的细节在利用阶段全部丢失；且 `pwn/reverse`（`shared=true`）二轮重试因 `if !shared` 守卫跳过了 `seedNonSharedWorkDir`，导致 `/work` 变空目录。
3. **热路径 I/O 与 Critic 同步阻塞**：每次只读 `Read/Grep/LS/ctf_http` 都重复 `Sync` 并全盘拷贝最多 32 个脚本算 SHA256；每连错 3 次就阻塞 20 秒调一次同步 `Critic LLM`，频繁打断正常 Exploit 偏移调试心流。
4. **上下文噪音与工具解锁税**：CTF 图谱携带大量恒为 0 的企业渗透字段（`findings_total`、`coverage` 等），`recent_facts` 不带 `detail` 逼迫模型二次调 `node_detail`；跨界题还需花 1 轮调 `ctf_unlock_toolpack`；提示词塞满 `Savepoint/Rewind/PlateauFork` 元说教。
5. **托管首轮一刀切早杀与 Hint 被动滞后**：首轮 `600s`（10 分钟）直接强杀正在写 exp 的中难题，且 Worker 无法在卡死时主动申请 Hint。

围绕这 5 大根因，**P4Y 落地了四大手术（12 项精确改造）+ 工具目录同步与容器轻量化补齐**。

---

## 三、 P4Y 核心优化思路与工程实现细节

### 3.1 手术一：执行引擎——从「僵化流水线」升级为「弹性三层多智能体」

| 改造项 | 核心思路 | 精确代码落点 |
| :--- | :--- | :--- |
| **0-LLM 目标物化** | 所有 `ZeroTouch` 与 `ctf/ad` 沙箱任务确定性创建唯一 Goal 节点，跳过 Round-0 LLM | [server/goals.go](../server/goals.go) `createGoals` |
| **0-LLM 直发 Lead-Solver** | Phase-0 `Sync/Precheck` 完成后自动直发 `phase="exploit", priority=8` 主攻意图，Turn 1 直入执行 | [server/goals.go](../server/goals.go) `startTaskEngine`、[server/server.go](../server/server.go) `seedCTFLeadSolverIntent` |
| **长程连续会话预算** | 非 `recon` 主攻意图步数下限抬升至 `80` 轮（支持 `0` 不限），墙钟下限 `20m`（多阶段获首枚 Flag 后自动升至 `30m`） | [agent/worker.go](../agent/worker.go) `ctfMaxTurnsForPhase`、[agent/ctf_tools.go](../agent/ctf_tools.go) `ctfRunBudgetForTask` |
| **Planner 心跳静默** | CTF 主攻意图运行中跳过 `heartbeat` 唤醒，仅在 `edge` 事件（完成/耗尽、阶段 Flag 验真、Hint 注入）时唤醒 Planner 战略分兵或 `steer_work` | [server/engine.go](../server/engine.go) `shouldSkipHeartbeatForCTFRunning` |
| **并发 `ask_helper(tasks[])`** | 支持单任务 `goal` 与最多 3 路 `tasks: [...]` 并发子代理扇出（共享 `/work`、独立上下文、只返浓缩结论） | [agent/helper.go](../agent/helper.go) `askHelperTool` |
| **单 Flag 确认零摩擦收口** | UI 模式确认单阶段 `flag` 候选时默认直接完结任务，免去收尾 `prove_goal + Verifier LLM` | [server/ctf.go](../server/ctf.go) `decideCTFFlag` |

### 3.2 手术二：沙箱与存储——全模式 `/work` 继承与热路径 I/O 降载

| 改造项 | 核心思路 | 精确代码落点 |
| :--- | :--- | :--- |
| **跨轮 `/work` 全继承** | 移除 `prepareSession` 中的 `if !shared` 守卫，无论 `shared=true`（Pwn/RE）还是 `shared=false`（Web/Misc/Crypto），新工作区均自动继承前序祖先任务与历史意图的具名脚本（`exp.py`、`*_patched` 等） | [ctf/service.go](../ctf/service.go) `prepareSession` |
| **`Sync` 内存缓存** | 基于 `root\|taskID` 与输入目录 `mtime` 实现 `ensureSynced`（2 分钟 TTL），热路径 `execute/StartJob` 免重复 DB 同步与 Precheck 扫描 | [ctf/service.go](../ctf/service.go) `ensureSynced` |
| **增量脚本快照缓存** | 基于 `(relPath, size, mtimeUnixNano)` 签名检测 `/work` 脏位（自动跳过 `.ghidra/.cache/.snapshots`），未修改脚本直接复用缓存元数据，免除每次 32 文件拷贝与 SHA256 | [ctf/service.go](../ctf/service.go) `snapshotScriptsCached` |
| **双面锚定预检标记** | 存在远程靶机时在 Precheck 摘要显式标注 `[LIVE TARGET PRESENT: ...]`，强制主攻手前 3 轮完成活体实测 | [ctf/precheck.go](../ctf/precheck.go) `RunPrecheck` |

### 3.3 手术三：督导、图谱与工具面——高信噪比与 0-LLM 督导

| 改造项 | 核心思路 | 精确代码落点 |
| :--- | :--- | :--- |
| **0-LLM 确定性 `Critic`** | 默认 `advisor` 改为 0ms 确定性模式匹配（识别 `502/断连`、`SIGSEGV/EOF/MOVAPS`、`401/403/404/WAF`、长停滞），0 Token、0 阻塞，保留自定义 `advisor` 注入钩子 | [agent/critic.go](../agent/critic.go) `deterministicCTFCriticAdvice` |
| **CTF 图谱去噪 + Fact 内联** | CTF 视图剔除 `findings_total`/`candidates_total`/`finding_list`/`awaiting_goal_evaluations`/`coverage`；`recent_facts` 直接内联 `detail(≤500字)` 与 `evidence(≤200字)` | [agent/tools.go](../agent/tools.go) `graphOverviewData`、[agent/worker.go](../agent/worker.go) `stripEnterpriseKeysForCTF`、[agent/planner.go](../agent/planner.go) |
| **跨界工具零轮次预解锁** | `ctfBase` 读取 Phase-0 Precheck 检出的文件类型与目标协议，自动激活对应跨界工具包（如 Web 含 ELF 自动激活 `binary` 包），保留纯单领域延迟加载契约 | [agent/ctf_tools.go](../agent/ctf_tools.go) `ctfBase` |
| **精简系统提示词** | 移除 `Savepoint/Rewind/PlateauFork` 冗长说教，聚焦活体优先、`/work/exp.py` 命名、并行 `ask_helper` 与红线纪律 | [agent/ctf_flow.go](../agent/ctf_flow.go) `ctfWorkerSystem` / `ctfPlannerSystem` |
| **UI 工具目录同步与清理** | 将 `py_repl`/`http_fuzz_diff`/`ask_helper`/`tips_search` 等新工具正式纳入前端工具管理目录，启动时自动清理已退役的内置 `ctf_python` | [agent/ctf_tools.go](../agent/ctf_tools.go) `ctfCatalogTools`、[server/assembly.go](../server/assembly.go) |

### 3.4 手术四：托管测评续航、受控 Hint 与容器补齐

| 改造项 | 核心思路 | 精确代码落点 |
| :--- | :--- | :--- |
| **托管首轮 20 分钟 + 动量延时** | `defaultHostedFirstPassTimeoutSec` 从 `600s` 升至 `1200s`；超时点若已获部分 Sub-Flag 或近 180s 内有新确认 Fact，自动授予一次 `+600s` 宽限期 | [server/benchmark.go](../server/benchmark.go) `checkChallengeTimeoutAndHint`, `hasRecentChallengeMomentum` |
| **8 分钟硬门禁主动 Hint** | 新增 `benchmark_request_hint` 工具：未满 8 分钟且未停滞时硬门禁拦截防偷懒扣分；达标后幂等拉取平台 Hint、写回图谱并直接返回当前 Worker | [agent/ctf_tools.go](../agent/ctf_tools.go)、[server/benchmark.go](../server/benchmark.go) `handleRequestHint` |
| **容器高频缺件微补** | 基于 5,088 次真实沙箱执行报错统计（缺失率仅 0.15%），以 `< 4.2 MB` 增量补齐 `iproute2`（`ip a/r`）与 `flask / itsdangerous / flask-unsign` | [Dockerfile.bench](../Dockerfile.bench)、[Dockerfile.ctf-tools](../Dockerfile.ctf-tools) |

---

## 四、 实战观测与关键架构权衡复盘

### 4.1 多阶段内网渗透实战验证（`b-01` / `b-02` / `b-03`）
在重构后的预览环境中同时开启三道 4~6 Flag 多阶段内网渗透题，实测观测到以下效果：
- **首动速度**：三道题均在创建后 **0 秒**直发 Lead-Solver，分别在 **2 分 19 秒（`b-02` 连拿 2 枚 Flag）**、**3 分 04 秒（`b-01` Flag 1）**、**3 分 13 秒（`b-03` Flag 1）** 破冰得分。
- **Planner 零空转**：连续运行 30+ 分钟内，`heartbeat` 触发 Planner 次数严格为 **`0`**；仅在阶段 Flag 验真、20 分钟交接与 Hint 到达时触发边沿规划（每题 4~5 轮），并成功演示了 Planner 收到 Hint 后不重复派发、而是直接通过 `steer_work` 精准纠偏在跑 Worker 的健康协同。
- **接力与分兵**：首轮 20 分钟结束后，三路 Lead-Solver 均沉淀了完整的交接 Fact（含 Webshell、socat 转发端口、MariaDB/Redis 密钥与已排除弱口令），Planner 随即按内网拓扑自动分兵多路并发 Worker 继续推进，零重复侦察。
- **Critic 零阻塞**：三题累计触发 17 次确定性 Critic 提醒，全程 0ms 延迟、0 阻塞 LLM 调用。

### 4.2 批判性架构权衡与 v0.92 二阶纠偏落地（避免后续踩坑）

1. **为什么 Web / 内网并发 Worker 的 `/work` 保持运行期隔离而非强行共享？**
   - `pwn/reverse` 单主攻互斥运行，共享 `shared/ctf-work` 无写冲突；而 Web/内网并发 Worker 同时改写 `exp.py` 或临时文件会产生竞态覆盖。当前采用“启动时继承前序快照、运行期各自隔离、下一轮自动合并”的折中方案最稳妥。
2. **为什么暂不通过 `steerBox` 向并发队友全量广播普通 `record_fact`，但必须 0-LLM 直推「平台 Hint」？**
   - `steerHooks.PreToolUse` 的机制是 `block=true` 硬拦截并消费 1 轮 LLM。全量广播队友普通 Fact 会打断心流、诱发串台；但**平台官方 Hint（每题最多 1 条）**是最高优先级破题钥匙——在 `b-02` 实战中发现 Hint 写入图谱后在跑 Worker 长达 28 分钟未感知，因此在 **v0.92** 落地了 `broadcastHintToRunningWorkers`，收到新 Hint 立即 0-LLM `SteerWork` 直达全部在跑 Worker。
3. **v0.92 五项二阶实战纠偏（针对 `b-01`/`b-02`/`b-03` 复盘落地）**：
   - **双层混合 Critic + 修复 `Write/Edit` 清零停滞计数 Bug**：3 连错保持 0-LLM 极速诊断（0ms）；连续 20 步无新 Fact 停滞时恢复调用 1 次真正的 LLM 深度语义证伪（单意图上限 2 次），且 `Write`/`Edit` 不再清零 `stagnantSamples`，彻底抓住“反复改脚本死循环”；
   - **进展感知型心跳（Progress-Aware Heartbeat）+ 20m 稳健预算**：`PlanHeartbeatSeconds` 设为 `480s`，健康推进的 Worker（运行 `< 10m` 或近 `8m` 有新确认 Fact）继续 0 心跳打扰；仅当连续停滞时放行 Planner 巡检止损，单意图上限稳健保持 `20m`；
   - **三大实战硬红线**：Docker 网关 `.1` 默认非靶机禁爆破；认证/爆破脚本必须先做 2 次独立请求核验一次性消费与多进程一致性（Oracle Sanity Check）；Planner 多阶段最多 2 路并发禁 3 路撞车。

---

## 五、 后续开发路线图（Roadmap）

供后续迭代按优先级推进：

### P0（高性价比近期增强）
1. **引导主攻手在内网多主机场景更早使用 `ask_helper(tasks=[...])`**：
   - 当前实测中主攻手在单会话内很少主动调 `ask_helper`。可在 `ctfWorkerSystem` 中补充明确触发条件：*“进入内网发现 ≥2 台存活主机或 ≥2 个独立服务端口时，立即用 `ask_helper(tasks=[...])` 并发扇出 2~3 个子代理同步摸排”*，把多路并发从第 20 分钟提前到第 5 分钟。
2. **非阻塞式高价值队友凭据同步（可选）**：
   - 若多阶段题高频出现“A 队友拿到密钥/凭据而 B 队友仍在盲测”，按第 4.2 节约束实现基于工具结果末尾追加（非 `PreToolUse` 拦截）的轻量级凭据广播，仅广播含 `password/secret/key/token/webshell/ssh` 的高置信度 `observed` Fact。

### P1（中期能力拓展）
3. **动态预算续期（In-Flight Budget Extension）**：
   - 当前 `ctfRunBudgetForTask` 仅在意图启动时计算一次（首轮 20m，二轮 30m）。若主攻手在第 15 分钟刚拿下一枚阶段 Flag，可在运行期内动态延长当前意图的 `MaxDuration`（例如 `+10m`），避免在连续破题高峰期被动中断交接。
4. **工具管理页按模式筛选与使用遥测可视化**：
   - 前端「工具管理」页目前混排展示 CTF、企业渗透（Pentest）与顶层编排（Orchestrator）全部 75+ 工具。可增加按模式标签筛选（`CTF` / `Pentest` / `Orchestrator`），并展示近 7 天调用次数与成功率。

### P2（长期演进）
5. **跨题经验进化闭环（TipCard 自动淘汰与权重衰减）**：
   - 基于 `ctf_tips` 的 `hit_count` 与 `solved_count` 统计有效转化率，自动降权低效或过时避坑卡，强化高质量题型经验沉淀。

---

## 六、 日常开发、测试与打包速查

```bash
# 1. 使用独立测试库运行全量 Go 单元测试（严禁使用线上/预览库）
docker run -d --rm --name p3y-unit-test-pg \
  -e POSTGRES_USER=p3y -e POSTGRES_PASSWORD=p3y -e POSTGRES_DB=p3y_test postgres:16-alpine
docker run --rm --link p3y-unit-test-pg:testpg --dns 223.5.5.5 \
  -e GOPROXY=https://goproxy.cn,direct \
  -e P3Y_PG_DSN="postgres://p3y:p3y@testpg:5432/p3y_test?sslmode=disable" \
  -v "$PWD:/src" -v p3y-go-modcache:/go/pkg/mod -v p3y-go-buildcache:/root/.cache/go-build \
  -w /src golang:1.26 go test -count=1 ./ctf/... ./ctfrunner/... ./agent/... ./server/... ./db/...
docker rm -f p3y-unit-test-pg

# 2. 编译 Linux amd64 嵌入式主二进制并增量更新本地预览容器
docker run --rm -v "$PWD:/src" -v p3y-go-modcache:/go/pkg/mod -v p3y-go-buildcache:/root/.cache/go-build \
  -w /src golang:1.26 sh -c "CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -tags embedui -ldflags='-s -w -X main.version=v0.91' -o dist/amd64/p3y ./cmd/p3y"
docker build -f Dockerfile.incremental --build-arg P3Y_BASE_IMAGE=p3y/p3y:v0.91 -t p3y/p3y:v0.91 .
docker compose --env-file data/ctf-preview.env -p p3y-preview -f docker-compose.ctf-preview.yml up -d --no-deps --force-recreate p3y

# 3. 重建单容器无头托管测评镜像并导出（要求 <= 3GB）
docker build -f Dockerfile.bench -t p3y-bench:latest .
docker save p3y-bench:latest | gzip -1 > p3y-bench-hosted.tar.gz
```
