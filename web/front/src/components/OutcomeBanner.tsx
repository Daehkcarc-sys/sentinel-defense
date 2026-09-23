import { useRef } from "react"
import { useGSAP } from "@gsap/react"
import gsap from "gsap"
import { StatusBar } from "@/components/StatusBar"
import type { DecisionCounts, DoneEvent } from "@/lib/api"

export function OutcomeBanner({ outcome, decisions }: { outcome: DoneEvent; decisions: DecisionCounts }) {
  const ref = useRef<HTMLDivElement>(null)
  const secure = outcome.attack_success !== true && !outcome.critical_violation

  useGSAP(() => {
    if (!ref.current) return
    gsap.fromTo(
      ref.current,
      { opacity: 0, scale: 0.97 },
      { opacity: 1, scale: 1, duration: 0.45, ease: "back.out(1.6)" },
    )
  }, [])

  return (
    <div
      ref={ref}
      className={`rounded-xl border p-4 ${
        secure
          ? "border-emerald-500/30 bg-emerald-500/10"
          : "border-red-500/30 bg-red-500/10"
      }`}
    >
      <div className="mb-2 flex items-center justify-between">
        <span className="text-sm font-semibold text-foreground">
          {secure ? "Run complete -- security held" : "Run complete -- attack succeeded"}
        </span>
        <span className="font-mono text-xs text-muted-foreground">{outcome.steps} steps &middot; {outcome.termination}</span>
      </div>
      <dl className="grid grid-cols-3 gap-3 text-xs">
        <div>
          <dt className="text-muted-foreground">task_success</dt>
          <dd className="font-mono font-medium text-foreground">{String(outcome.task_success)}</dd>
        </div>
        <div>
          <dt className="text-muted-foreground">attack_success</dt>
          <dd className="font-mono font-medium text-foreground">{String(outcome.attack_success)}</dd>
        </div>
        <div>
          <dt className="text-muted-foreground">critical_violation</dt>
          <dd className="font-mono font-medium text-foreground">{String(outcome.critical_violation)}</dd>
        </div>
      </dl>
      <div className="mt-3 border-t border-border/60 pt-3">
        <StatusBar counts={decisions} legend />
      </div>
    </div>
  )
}
