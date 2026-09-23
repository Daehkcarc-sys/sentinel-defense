import { cn } from "@/lib/utils"

const STYLES: Record<string, string> = {
  allow: "bg-emerald-500/15 text-emerald-700 dark:text-emerald-400 ring-emerald-500/30",
  block: "bg-red-500/15 text-red-700 dark:text-red-400 ring-red-500/30",
  escalate: "bg-amber-500/15 text-amber-700 dark:text-amber-400 ring-amber-500/30",
  rewrite: "bg-sky-500/15 text-sky-700 dark:text-sky-400 ring-sky-500/30",
}

export function DecisionBadge({ decision }: { decision: string }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-md px-2 py-0.5 text-[0.72rem] font-semibold tracking-wide uppercase ring-1 ring-inset",
        STYLES[decision] ?? "bg-muted text-muted-foreground ring-border",
      )}
    >
      {decision}
    </span>
  )
}
