import * as React from "react";

import { cn } from "@/lib/utils";

interface P3YLogoProps {
  /** "mark": 侧栏 / 图标用紧凑彩色徽标；"hero": 登录页 / 初始化页左侧深色背景展示用纯白主视觉。 */
  variant?: "mark" | "hero";
  className?: string;
}

export function P3YLogo({ variant = "mark", className }: P3YLogoProps) {
  const gradId = React.useId();

  if (variant === "hero") {
    return (
      <div className={cn("relative flex flex-col items-center justify-center gap-4 text-primary-foreground select-none", className)}>
        <svg
          viewBox="0 0 128 128"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
          className="size-32 drop-shadow-[0_0_24px_rgba(255,255,255,0.22)]"
          aria-hidden="true"
        >
          {/* 外层六边形战术盾框 */}
          <path
            d="M64 8L112 32V74C112 97.5 91.2 114.4 64 121C36.8 114.4 16 97.5 16 74V32L64 8Z"
            stroke="currentColor"
            strokeOpacity="0.32"
            strokeWidth="2.5"
          />
          <path
            d="M64 16L104 36V72.5C104 92 86.5 106.5 64 112.5C41.5 106.5 24 92 24 72.5V36L64 16Z"
            fill="currentColor"
            fillOpacity="0.08"
            stroke="currentColor"
            strokeWidth="3.5"
            strokeLinejoin="round"
          />
          {/* 内部 Y 型三向矢量棱镜（象征 P3Y 三元协同与自主攻防决策） */}
          <path
            d="M40 44L64 59L88 44"
            stroke="currentColor"
            strokeWidth="6.5"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
          <path
            d="M64 59V94"
            stroke="currentColor"
            strokeWidth="6.5"
            strokeLinecap="round"
          />
          {/* 顶部三棱节点与中心核心锁点 */}
          <circle cx="40" cy="44" r="4.5" fill="currentColor" />
          <circle cx="88" cy="44" r="4.5" fill="currentColor" />
          <circle cx="64" cy="94" r="4.5" fill="currentColor" />
          <circle cx="64" cy="59" r="7" fill="currentColor" />
          {/* 战术扫描微角标 */}
          <path d="M51 31L64 25L77 31" stroke="currentColor" strokeOpacity="0.55" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
        <div className="flex flex-col items-center gap-1">
          <span className="font-bold text-3xl tracking-[0.34em] pl-[0.34em]">P4Y</span>
          <span className="font-mono text-[10px] tracking-[0.28em] pl-[0.28em] opacity-65">AUTONOMOUS SECURITY</span>
        </div>
      </div>
    );
  }

  return (
    <svg
      viewBox="0 0 64 64"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={cn("size-7 shrink-0", className)}
      aria-hidden="true"
    >
      <defs>
        <linearGradient id={gradId} x1="6" y1="4" x2="58" y2="60" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#4F46E5" />
          <stop offset="55%" stopColor="#7C3AED" />
          <stop offset="100%" stopColor="#06B6D4" />
        </linearGradient>
      </defs>
      <rect x="4" y="4" width="56" height="56" rx="15" fill={`url(#${gradId})`} />
      <path
        d="M32 12L50 21V36.5C50 45.2 42.3 51.6 32 54.4C21.7 51.6 14 45.2 14 36.5V21L32 12Z"
        stroke="white"
        strokeOpacity="0.92"
        strokeWidth="2.6"
        strokeLinejoin="round"
        fill="white"
        fillOpacity="0.1"
      />
      <path
        d="M22.5 25L32 31L41.5 25M32 31V44.5"
        stroke="white"
        strokeWidth="3.4"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <circle cx="22.5" cy="25" r="2.3" fill="white" />
      <circle cx="41.5" cy="25" r="2.3" fill="white" />
      <circle cx="32" cy="44.5" r="2.3" fill="white" />
      <circle cx="32" cy="31" r="3.4" fill="white" />
    </svg>
  );
}
