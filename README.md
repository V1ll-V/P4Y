# P4Y

**P4Y** 是继承自 **P3Y** 项目并围绕 **第一性原理（First Principles）** 与 **“Less is More”** 理念完成深度重构的新一代自主攻防与 CTF 解题智能体系统。

系统面向 **CTF 自动求解**、**多阶段内网渗透**、**Attack-Defense 实时攻防** 与 **多平台零交互自动化测评（Hosted Benchmark）**，核心由 **Go 控制面（`cmd/p3y`）**、**物理隔离沙箱执行器（`cmd/p3y-box` / 本地无 Docker 沙箱）** 与 **嵌入式控制台（`web/`）** 组成。

---

## P4Y 相对 P3Y 的核心演进

在完整继承 P3Y 探索图黑板、沙箱物理隔离、VPN Sidecar 复用、TipCard 避坑卡与多平台测评基础设施的基础上，P4Y 针对端到端解题速度、推理连续性与多阶段吞吐完成了四大架构级重构：

1. **0-LLM 直通车 `Lead-Solver` + 弹性三层多智能体架构**：
   - **首动延迟归零**：CTF / 沙箱任务跳过 `Round-0 Goals LLM` 与 `Round-1 Planner LLM`，在 0-LLM `Phase-0 Precheck` 完成后直接点火长程主攻手 `Lead-Solver`（默认 `80+` 轮 / `20~30` 分钟连续会话），Turn 1 直发沙箱探测命令。
   - **三层按需伸缩**：
     - **L1 单兵直通层**：单题与多阶段外网破冰期由单个连续会话一气呵成，消灭 `Recon → Planner → Exploit` 交接失忆；
     - **L2 内生并行层**：主攻手内部通过升级版 `ask_helper(tasks=[...])` 可随时并发扇出最多 **3 路**短周期子代理，共享 `/work` 完成重型审计与并行分析而不污染主上下文；
     - **L3 战略分兵层**：主攻运行期间静默 Planner 周期心跳空转（0 次无效 heartbeat 唤醒），仅在边沿事件（阶段 Flag 验真、单路耗尽、收到 Hint、候选打回）时唤醒 Planner 进行多目标分兵与 `steer_work` 实时纠偏。
2. **全模式 `/work` 跨轮继承 + 热路径 I/O 降载**：
   - 统一共享模式（`pwn` / `reverse`）与隔离模式（`web` / `misc` / `crypto`）的祖先任务产物合并逻辑，二轮重跑 100% 继承前序 `/work/exp.py`、`*_patched` 等持久化产物。
   - 引入任务级 `Sync` 内存缓存（`ensureSynced`）与基于 `(relPath, size, mtime)` 签名的脚本增量快照缓存（`snapshotScriptsCached`），消除只读工具调用时的重复预检与全盘 32 文件拷贝哈希开销。
3. **0-LLM 确定性 `Critic` + 高信噪比 CTF 图谱与跨界零轮次工具解锁**：
   - 将原 20 秒同步阻塞式 `Critic LLM` 替换为 **0-LLM、0ms 确定性特征诊断引擎**（精准识别 `502/断连`、`SIGSEGV/EOF/MOVAPS`、HTTP 403/404 盲扫与长停滞），绝不打断正常利用调试心流。
   - CTF 图谱视图彻底剥离企业渗透专属空字段（`findings_total`、`candidates_total`、`finding_list`、`coverage` 等），并在 `recent_facts` 中**直接内联 `detail`（≤500字）与 `evidence`（≤200字）**，免除二次 `node_detail` 盲查。
   - 基于 Phase-0 Precheck 检出的跨界特征（如 Web 题含 ELF/PCAP、Pwn 题含 HTTP 靶机）在 Turn 1 自动预解锁对应领域工具包，消除跨界工具解锁轮次税；同时植入「双面锚定法则（`[LIVE TARGET PRESENT]`）」，强制有活体靶机时前 3 轮完成活体实测验证。
4. **托管测评续航升级与受控主动 Hint**：
   - 托管模式首轮预算上调至 **`1200s`（20 分钟）**，并新增 **临门一脚动量延时（Momentum Grace Window）**：到达超时点时若已获部分 Sub-Flag 或近 3 分钟内有新确认 Fact 产出，自动宽限 **`+600s`** 避免临门错杀。
   - 新增带 **8 分钟防偷懒硬门禁** 的主动 `benchmark_request_hint` 工具（全局幂等缓存并自动写回图谱），帮助模型在真正卡死于脑洞/隐藏条件时及时破局。

---

## 系统架构

```text
  浏览器控制台 (Next.js, embedui) / 无头托管模式 (P3Y_HEADLESS=1)
               │  HTTP / SSE / JWT
               ▼
  ┌──────────────────────────────────────────────────────────┐
  │ cmd/p3y 控制面                                            │
  │  ├── 弹性调度引擎: Direct Lead-Solver / Edge Planner      │
  │  ├── 并行协查与督导: ask_helper(tasks[]) / 0-LLM Critic   │
  │  ├── 业务域:       CTF / AD / Benchmark / Intercept       │
  │  ├── LLM 池:       多 Profile Failover + llmrec 全量审计  │
  │  ├── MITM 代理:    127.0.0.1:8788 流量捕获与取证          │
  │  └── PostgreSQL:   探索图 / 看板 / TipCard / 任务与快照   │
  └──────────────────────────┬───────────────────────────────┘
                             │  HTTP + Bearer Token（或单容器 LocalBackend）
                             ▼
  ┌──────────────────────────────────────────────────────────┐
  │ 隔离执行面（cmd/p3y-box 守护进程 / 单容器本地沙箱）        │
  │  ├── 工具容器: /work (rw 持久继承) + /work/.inputs (ro)   │
  │  ├── 交互/作业: PTY 伪终端、PyREPL、后台长作业与超时隔离  │
  │  ├── 快照引擎: /work 硬链接 Savepoint / Rewind            │
  │  └── VPN 网关: p3y-box-vpn-<hash> 同配置共享隧道          │
  └──────────────────────────────────────────────────────────┘
```

---

## 核心模块与能力速览

| 目录 | 职责 |
| :--- | :--- |
| `cmd/p3y` / `cmd/p3y-box` | 主控制面二进制入口 / 独立容器沙箱守护进程入口 |
| `server/` | HTTP/SSE API 路由、事件驱动调度引擎（`engine.go`）、0-LLM 目标与主攻直发（`goals.go`）、`BenchmarkManager`（`benchmark.go`） |
| `agent/` | Lead-Solver / Planner / 并发 `ask_helper` / 0-LLM `Critic` / 图谱与工具目录（`ctf_tools.go`、`toolcatalog.go`） |
| `ctf/` / `ctfrunner/` | Phase-0 Precheck、动态二次 `TipCard` 召回与结晶、增量脚本快照与 `Sync` 缓存、`PyREPL`、WP 生成 / Docker 与本地无头沙箱引擎 |
| `benchmark/` | TSecBench REST、CTF2 / DASCTF MCP、Generic MCP 适配器与 `Skill.zip` 解析器 |
| `ad/` | Attack-Defense `Lead` / `Repeater` / `Catcher` / `Patcher` |
| `db/` | PostgreSQL Schema 与迁移、探索图存储、只读血缘继承、测评与通知持久化 |
| `llmpool/` / `llmrec/` | 多配置 LLM 健康度与 Failover 池 / 原生请求响应全量审计 |
| `traffic/` / `intercept/` | MITM HTTP 抓包与归档 / 高危操作人工审批规则与上下文 |
| `web/` | Next.js + React + Tailwind 前端控制台（支持静态导出并通过 `embedui` 嵌入二进制） |

---

## 部署与运行

### 环境要求
- **容器部署**：Docker & Docker Compose（内置 PostgreSQL 16）
- **源码构建 / 开发（可选）**：Go `1.26+`、Node.js `20+`

---

### 方式一：完整 CTF / AD / Benchmark 沙箱预览环境

启用隔离沙箱执行器 `p3y-box`、全套 CTF 工具容器（含 Ghidra、radare2、pwntools、angr、python-sat、iproute2、flask-unsign、离线 glibc 池等）以及 WireGuard / OpenVPN Sidecar（编排文件：`docker-compose.ctf-preview.yml`）：

1. **构建主镜像与底层沙箱镜像**

   ```bash
   # 1) 构建前端并编译主二进制
   cd web && npm ci && npm run build:static && cd ..
   rm -rf server/webui/dist && cp -r web/out server/webui/dist
   CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -tags embedui -ldflags='-s -w -X main.version=v0.91' -o dist/amd64/p3y ./cmd/p3y
   docker build -t p3y/p3y:v0.91 .

   # 2) 构建执行器 p3y-box 与 VPN / 工具镜像
   CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags='-s -w' -o dist/amd64/p3y-box ./cmd/p3y-box
   docker build -f Dockerfile.ctf-runner -t p3y/p3y-box:0.9.0 .
   docker build -f Dockerfile.ctf-wg -t p3y/p3y-box-wg:0.9.0 .
   docker build -f Dockerfile.ctf-tools -t p3y/p3y-box-tools:20261113 .
   ```

2. **创建环境变量文件 `data/ctf-preview.env`**

   ```env
   P3Y_PREVIEW_DB_PASSWORD=change-me-strong-password
   P3Y_BOX_TOKEN=replace-with-at-least-24-chars-random-token
   P3Y_CTF_FLAG_PREFIXES=flag,ctf,p4y
   ```

3. **启动服务**

   ```bash
   docker compose --env-file data/ctf-preview.env -p p3y-preview -f docker-compose.ctf-preview.yml up -d
   ```

   控制台访问 `http://127.0.0.1:8789`。

---

### 方式二：单容器无头托管测评镜像（Hosted Benchmark）

内置 PostgreSQL 16、本地无 Docker 沙箱（`P3Y_BOX_LOCAL=1`）、完整 CTF 工具链与离线武库种子，直接用于平台托管评测或离线单容器批测：

```bash
docker build -f Dockerfile.bench -t p3y-bench:latest .
docker save p3y-bench:latest | gzip -1 > p3y-bench-hosted.tar.gz
```

---

### 方式三：本地源码开发与测试

```bash
# 配置独立测试数据库并运行全量单元测试
export P3Y_PG_DSN="postgres://p3y:p3y@127.0.0.1:5432/p3y_test?sslmode=disable"
go test -count=1 ./ctf/... ./ctfrunner/... ./agent/... ./server/... ./db/...

# 前端类型校验与静态导出构建
cd web && npx tsc --noEmit && npm run build:static
```
