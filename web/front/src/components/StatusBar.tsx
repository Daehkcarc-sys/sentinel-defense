import { CheckCircle2, Ban, AlertTriangle, Wand2 } from "lucide-react"
import type { DecisionCounts } from "@/lib/api"

// Fixed identity mapping, used everywhere a decision appears (DecisionBadge included) --
// color always follows the entity, never re-cycled per chart.
const SEGMENTS: { key: keyof DecisionCounts; label: string; className: string; Icon: typeof CheckCircle2 }[] = [
  { key: "allow", label: "Allow", className: "bg-emerald-500", Icon: CheckCircle2 },
  { key: "escalate", label: "Escalate", className: "bg-amber-500", Icon: AlertTriangle },
  { key: "rewrite", label: "Rewrite", className: "bg-sky-500", Icon: Wand2 },
  { key: "block", label: "Block", className: "bg-red-500", Icon: Ban },
]

export function StatusBar({
  counts,
  size = "md",
  legend = false,
}: {
  counts: DecisionCounts
  size?: "sm" | "md"
  legend?: boolean
}) {
  const total = counts.allow + counts.block + counts.escalate + counts.rewrite
  const height = size === "sm" ? "h-1.5" : "h-3"

  if (total === 0) {
    return <div className={`${height} w-full rounded-full bg-muted`} />
  }

  return (
    <div className="flex flex-col gap-1.5">
      <div className={`flex w-full gap-0.5 overflow-hidden rounded-full ${height}`}>
        {SEGMENTS.filter((s) => counts[s.key] > 0).map((s) => (
          <div
            key={s.key}
            title={`${s.label}: ${counts[s.key]} of ${total}`}
            className={`${s.className} h-full transition-[width] duration-300`}
            style={{ width: `${(counts[s.key] / total) * 100}%` }}
          />
        ))}
      </div>
      {legend && (
        <div className="flex flex-wrap items-center gap-3">
          {SEGMENTS.map((s) => (
            <div key={s.key} className="flex items-center gap-1 text-[0.68rem] text-muted-foreground">
              <s.Icon className={`size-3 ${s.className.replace("bg-", "text-")}`} />
              {s.label}
              <span className="font-mono tabular-nums text-foreground">{counts[s.key]}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
