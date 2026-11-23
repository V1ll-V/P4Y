"use client";

import * as React from "react";
import Link from "next/link";
import { ArrowUpRightIcon, PlusIcon, TrophyIcon } from "lucide-react";

import { Button } from "@/components/ui/button";
import { APP_CONFIG } from "@/config/app-config";
import { api } from "@/lib/api";
import type { Activity, BenchmarkSession, BoardKit, LLMProfile, Settings, Task, TipCard } from "@/lib/types";
import { cn } from "@/lib/utils";

function fmtRel(ts?: string | number | null): string {
  if (!ts) return "—";
  const ms = Date.now() - (typeof ts === "number" ? (ts > 1e12 ? ts : ts * 1000) : Date.parse(ts));
  if (!Number.isFinite(ms) || ms < 0) return "刚刚";
  const s = Math.floor(ms / 1000);
  if (s < 60) return `${s}s 前`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m 前`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h 前`;
  return `${Math.floor(h / 24)}d 前`;
}

function fmtClock(ts?: string | number | null): string {
  if (!ts) return "--:--:--";
  const d = new Date(typeof ts === "number" ? (ts > 1e12 ? ts : ts * 1000) : ts);
  if (Number.isNaN(d.getTime())) return "--:--:--";
  return d.toLocaleTimeString("zh-CN", { hour12: false });
}

function statusDotClass(status: string): string {
  switch (status) {
    case "running":
    case "created":
      return "bg-blue-500 animate-pulse";
    case "done":
      return "bg-emerald-500";
    case "paused":
    case "timeout":
      return "bg-amber-500";
    case "failed":
      return "bg-red-500";
    default:
      return "bg-muted-foreground/50";
  }
}

function statusLabel(status: string): string {
  switch (status) {
    case "running":
    case "created":
      return "运行中";
    case "done":
      return "已通关";
    case "paused":
      return "已暂停";
    case "timeout":
      return "已超时";
    case "failed":
      return "失败";
    default:
      return status || "未知";
  }
}

function activityTag(kind: string): { label: string; accent: boolean } {
  switch (kind) {
    case "round":
      return { label: "PLAN", accent: false };
    case "critic":
      return { label: "CRITIC", accent: false };
    case "helper_start":
    case "helper_done":
      return { label: "HELPER", accent: false };
    case "tool":
      return { label: "TOOL", accent: false };
    default:
      return { label: "LIVE", accent: true };
  }
}

export default function DashboardPage() {
  const [tasks, setTasks] = React.useState<Task[]>([]);
  const [activity, setActivity] = React.useState<Activity[]>([]);
  const [benchmarks, setBenchmarks] = React.useState<BenchmarkSession[]>([]);
  const [tips, setTips] = React.useState<TipCard[]>([]);
  const [kits, setKits] = React.useState<BoardKit[]>([]);
  const [profiles, setProfiles] = React.useState<LLMProfile[]>([]);
  const [settings, setSettings] = React.useState<Settings | null>(null);

  React.useEffect(() => {
    let alive = true;
    const loadFast = async () => {
      try {
        const [tr, act, bench] = await Promise.all([
          api.tasks(),
          api.activity(undefined, { limit: 20 }),
          api.benchmarkListSessions().catch(() => [] as BenchmarkSession[]),
        ]);
        if (!alive) return;
        setTasks(tr.tasks ?? []);
        setActivity(act.items ?? []);
        setBenchmarks(bench ?? []);
      } catch {
        /* retry on next poll */
      }
    };
    void loadFast();
    const t = setInterval(loadFast, 5000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, []);

  React.useEffect(() => {
    let alive = true;
    const loadSlow = async () => {
      try {
        const [tipList, kitList, profList, cfg] = await Promise.all([
          api.listTips({ limit: 200 }).catch(() => [] as TipCard[]),
          api.listKits({ limit: 200 }).catch(() => [] as BoardKit[]),
          api.llmProfiles().catch(() => [] as LLMProfile[]),
          api.settings().catch(() => null),
        ]);
        if (!alive) return;
        setTips(tipList);
        setKits(kitList);
        setProfiles(profList);
        setSettings(cfg);
      } catch {
        /* retry on next poll */
      }
    };
    void loadSlow();
    const t = setInterval(loadSlow, 20000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, []);

  const runningTasks = React.useMemo(
    () => tasks.filter((t) => (t.status === "running" || t.status === "created") && !t.paused),
    [tasks],
  );
  const doneTasks = React.useMemo(() => tasks.filter((t) => t.status === "done"), [tasks]);
  const recentTasks = React.useMemo(() => tasks.slice(0, 10), [tasks]);
  const activeBench = React.useMemo(() => benchmarks.find((b) => b.status === "running") ?? benchmarks[0] ?? null, [benchmarks]);
  const activeProfile = React.useMemo(() => profiles[0] ?? null, [profiles]);

  const solveRate = tasks.length > 0 ? Math.round((doneTasks.length / tasks.length) * 100) : 0;

  return (
    <div className="mx-auto w-full max-w-[1360px] space-y-6 pb-8">
      {/* 顶部极简操作栏 */}
      <header className="flex flex-wrap items-center justify-between gap-4 border-b border-border pb-4">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-lg font-semibold tracking-tight">作战总览</h1>
            <span className="rounded border border-border bg-card px-1.5 py-0.5 font-mono text-[11px] text-muted-foreground">
              {APP_CONFIG.name} {APP_CONFIG.displayVersion}
            </span>
          </div>
          <p className="mt-0.5 text-xs text-muted-foreground">
            0-LLM 直发 Lead-Solver · 双层混合 Critic · 进展感知型巡检
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button asChild variant="outline" size="sm" className="h-8 gap-1.5 text-xs">
            <Link prefetch={false} href="/benchmark">
              <TrophyIcon className="size-3.5" />
              自动测评
            </Link>
          </Button>
          <Button asChild size="sm" className="h-8 gap-1.5 text-xs">
            <Link prefetch={false} href="/function/tasks">
              <PlusIcon className="size-3.5" />
              新建任务
            </Link>
          </Button>
        </div>
      </header>

      {/* 4 格极简 KPI */}
      <section className="grid grid-cols-2 gap-3.5 lg:grid-cols-4">
        <div className="rounded-lg border border-border bg-card p-4">
          <div className="flex items-center justify-between text-xs text-muted-foreground">
            <span>运行中任务</span>
            <span className={cn("size-1.5 rounded-full", runningTasks.length > 0 ? "bg-blue-500 animate-pulse" : "bg-muted-foreground/40")} />
          </div>
          <div className="mt-2 font-mono text-2xl font-semibold tabular-nums tracking-tight">{runningTasks.length}</div>
          <div className="mt-1 truncate text-xs text-muted-foreground">
            {runningTasks[0] ? `${runningTasks[0].name}` : "当前空闲待命"}
          </div>
        </div>

        <div className="rounded-lg border border-border bg-card p-4">
          <div className="flex items-center justify-between text-xs text-muted-foreground">
            <span>累计通关</span>
            <span className="size-1.5 rounded-full bg-emerald-500" />
          </div>
          <div className="mt-2 font-mono text-2xl font-semibold tabular-nums tracking-tight">{doneTasks.length}</div>
          <div className="mt-1 text-xs text-muted-foreground">
            共 <span className="font-mono">{tasks.length}</span> 个任务 · 通关率 <span className="font-mono">{solveRate}%</span>
          </div>
        </div>

        <div className="rounded-lg border border-border bg-card p-4">
          <div className="flex items-center justify-between text-xs text-muted-foreground">
            <span>自动测评</span>
            <span className={cn("size-1.5 rounded-full", activeBench?.status === "running" ? "bg-blue-500 animate-pulse" : "bg-emerald-500")} />
          </div>
          <div className="mt-2 font-mono text-2xl font-semibold tabular-nums tracking-tight">
            {activeBench ? `${activeBench.completed_count}/${activeBench.total_count}` : "—"}
          </div>
          <div className="mt-1 truncate text-xs text-muted-foreground">
            {activeBench ? `${activeBench.name} · ${activeBench.total_score}/${activeBench.max_possible_score} 分` : `共 ${benchmarks.length} 个测评会话`}
          </div>
        </div>

        <div className="rounded-lg border border-border bg-card p-4">
          <div className="flex items-center justify-between text-xs text-muted-foreground">
            <span>武库与套件</span>
            <span className="size-1.5 rounded-full bg-muted-foreground/50" />
          </div>
          <div className="mt-2 font-mono text-2xl font-semibold tabular-nums tracking-tight">{tips.length}</div>
          <div className="mt-1 text-xs text-muted-foreground">
            避坑卡 · <span className="font-mono">{kits.length}</span> 套可复用套件
          </div>
        </div>
      </section>

      {/* 主体双栏：左最近任务 + 右实时战况流 */}
      <section className="grid grid-cols-1 gap-5 lg:grid-cols-3">
        {/* 最近任务 */}
        <div className="overflow-hidden rounded-lg border border-border bg-card lg:col-span-2">
          <div className="flex items-center justify-between border-b border-border px-4 py-3">
            <span className="text-xs font-medium">最近任务</span>
            <Link prefetch={false} href="/function/tasks" className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground">
              全部任务
              <ArrowUpRightIcon className="size-3" />
            </Link>
          </div>
          {recentTasks.length === 0 ? (
            <div className="px-4 py-12 text-center text-xs text-muted-foreground">暂无任务，点击右上角「新建任务」开始。</div>
          ) : (
            <div className="divide-y divide-border">
              {recentTasks.map((t) => (
                <Link
                  key={t.id}
                  prefetch={false}
                  href={`/function/tasks/detail?id=${encodeURIComponent(t.id)}`}
                  className="flex items-center justify-between gap-4 px-4 py-3 transition-colors hover:bg-accent/50"
                >
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <span className={cn("size-1.5 shrink-0 rounded-full", statusDotClass(t.status))} />
                      <span className="font-mono text-xs text-muted-foreground">#{t.id}</span>
                      <span className="truncate text-sm font-medium">{t.name}</span>
                      {t.challenge_type && (
                        <span className="hidden rounded border border-border px-1.5 py-0.5 font-mono text-[10px] uppercase text-muted-foreground sm:inline">
                          {t.challenge_type}
                        </span>
                      )}
                    </div>
                    {t.goal && (
                      <p className="mt-1 truncate pl-3.5 text-xs text-muted-foreground">{t.goal}</p>
                    )}
                  </div>
                  <div className="shrink-0 text-right">
                    <div className="text-xs font-medium text-foreground">{statusLabel(t.status)}</div>
                    <div className="mt-0.5 font-mono text-[11px] text-muted-foreground">{fmtRel(t.completed_at || t.created_at)}</div>
                  </div>
                </Link>
              ))}
            </div>
          )}
        </div>

        {/* 实时战况流 */}
        <div className="flex flex-col overflow-hidden rounded-lg border border-border bg-card">
          <div className="flex items-center justify-between border-b border-border px-4 py-3">
            <span className="text-xs font-medium">实时战况流</span>
            <span className="font-mono text-[11px] text-emerald-500">LIVE</span>
          </div>
          {activity.length === 0 ? (
            <div className="px-4 py-12 text-center text-xs text-muted-foreground">暂无实时动态</div>
          ) : (
            <div className="max-h-[520px] flex-1 space-y-3.5 overflow-y-auto p-4">
              {activity.slice(0, 14).map((ev, idx) => {
                const tag = activityTag(ev.kind);
                return (
                  <div key={`${ev.ts ?? ""}-${idx}`} className="flex gap-2.5 text-xs">
                    <span className="shrink-0 pt-0.5 font-mono text-[11px] text-muted-foreground">
                      {fmtClock(ev.ts)}
                    </span>
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-1.5">
                        <span
                          className={cn(
                            "rounded bg-muted px-1.5 py-0.5 font-mono text-[10px]",
                            tag.accent ? "text-emerald-500" : "text-muted-foreground",
                          )}
                        >
                          {tag.label}
                        </span>
                        {ev.worker && <span className="truncate font-mono text-[11px] font-medium">{ev.worker}</span>}
                      </div>
                      <p className="mt-1 line-clamp-2 leading-relaxed text-muted-foreground">{ev.summary}</p>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </section>

      {/* 底部极简运行时状态条 */}
      <footer className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-border bg-card px-4 py-2.5 text-xs text-muted-foreground">
        <div className="flex flex-wrap items-center gap-4 font-mono">
          <span>
            LLM: <strong className="font-medium text-foreground">{activeProfile ? `${activeProfile.format} / ${activeProfile.model}` : "未配置"}</strong>
          </span>
          {settings && (
            <span>
              Workers: <strong className="font-medium text-foreground">{settings.workers}</strong>
            </span>
          )}
        </div>
        <div className="flex items-center gap-4">
          <Link prefetch={false} href="/system/llm" className="hover:text-foreground">模型配置</Link>
          <Link prefetch={false} href="/system/agents" className="hover:text-foreground">智能体调优</Link>
          <Link prefetch={false} href="/function/kits" className="hover:text-foreground">武库管理</Link>
        </div>
      </footer>
    </div>
  );
}
