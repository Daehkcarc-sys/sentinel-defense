import { useRef } from "react"
import { useGSAP } from "@gsap/react"
import gsap from "gsap"
import { DecisionBadge } from "@/components/DecisionBadge"
import { ReasonCode } from "@/components/ReasonCode"
import type { DecisionEvent } from "@/lib/api"

function RiskMeter({ label, value }: { label: string; value: number }) {
  return (
    <div className="flex items-center gap-2">
      <span className="w-16 shrink-0 text-[0.68rem] uppercase tracking-wide text-muted-foreground">{label}</span>
      <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-muted">
        <div
          className="h-full rounded-full bg-foreground/70 transition-[width] duration-500 ease-out"
          style={{ width: `${Math.round(value * 100)}%` }}
        />
      </div>
      <span className="w-9 shrink-0 text-right text-[0.68rem] tabular-nums text-muted-foreground">
        {value.toFixed(2)}
      </span>
    </div>
  )
}

export function DecisionCard({ event, index }: { event: DecisionEvent; index: number }) {
  const ref = useRef<HTMLDivElement>(null)

  useGSAP(
    () => {
      if (!ref.current) return
      gsap.fromTo(
        ref.current,
        { opacity: 0, y: 14, filter: "blur(4px)" },
        { opacity: 1, y: 0, filter: "blur(0px)", duration: 0.5, delay: index * 0.03, ease: "power3.out" },
      )
    },
    { scope: ref, dependencies: [event.step_id] },
  )

  return (
    <div
      ref={ref}
      className="rounded-xl border border-border bg-card p-4 shadow-sm"
      data-slot="decision-card"
    >
      <div className="mb-2 flex items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <span className="font-mono text-xs text-muted-foreground">step {event.step_id}</span>
          <span className="text-sm font-medium text-foreground">
            {event.action_type}
            {event.tool ? <span className="text-muted-foreground"> &middot; {event.tool}</span> : null}
          </span>
        </div>
        <DecisionBadge decision={event.decision} />
      </div>

      {event.arguments && Object.keys(event.arguments).length > 0 && (
        <div className="mb-2 rounded-lg bg-muted/60 px-3 py-2 font-mono text-[0.72rem] leading-relaxed text-foreground/80">
          {Object.entries(event.arguments).map(([k, v]) => {
            const rewrittenValue = event.rewritten_arguments?.[k]
            const changed = event.decision === "rewrite" && rewrittenValue !== undefined && rewrittenValue !== v
            return (
              <div key={k} className="truncate">
                <span className="text-muted-foreground">{k}</span>:{" "}
                {changed ? (
                  <>
                    <span className="text-red-600 line-through dark:text-red-400">{String(v)}</span>{" "}
                    <span className="text-sky-700 dark:text-sky-400">&rarr; {String(rewrittenValue)}</span>
                  </>
                ) : (
                  String(v)
                )}
              </div>
            )
          })}
        </div>
      )}

      {event.content && (
        <p
          className={`mb-1 rounded-lg border px-3 py-2 text-sm leading-relaxed ${
            event.decision === "rewrite" && event.rewritten_content
              ? "border-red-500/25 bg-red-500/5 text-foreground/60 line-through decoration-red-500/40"
              : "border-border/70 bg-background/50 text-foreground/90"
          }`}
        >
          {event.decision === "rewrite" && event.rewritten_content ? (
            <span className="mr-2 rounded bg-muted px-1.5 py-0.5 text-[0.65rem] font-semibold uppercase tracking-wide text-muted-foreground no-underline">
              candidate draft
            </span>
          ) : null}
          {event.content}
        </p>
      )}

      {event.decision === "rewrite" && event.rewritten_content && (
        <p className="mb-3 rounded-lg border border-sky-500/30 bg-sky-500/5 px-3 py-2 text-sm leading-relaxed text-foreground/90">
          <span className="mr-2 rounded bg-sky-500/15 px-1.5 py-0.5 text-[0.65rem] font-semibold uppercase tracking-wide text-sky-700 dark:text-sky-400">
            delivered
          </span>
          {event.rewritten_content}
        </p>
      )}

      <div className="mb-3 grid grid-cols-1 gap-1.5 sm:grid-cols-2">
        <RiskMeter label="risk" value={event.risk_score} />
        <RiskMeter label="conf." value={event.confidence} />
      </div>

      <div className="flex flex-wrap items-center gap-1.5">
        {event.reason_codes.map((code) => (
          <ReasonCode key={code} code={code} />
        ))}
        <span className="ml-auto font-mono text-[0.68rem] text-muted-foreground">
          {event.latency_ms.toFixed(2)} ms
        </span>
      </div>
    </div>
  )
}
