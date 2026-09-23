import { motion } from "motion/react"
import { GaugeBar } from "@/components/GaugeBar"
import { StatusBar } from "@/components/StatusBar"
import type { BulkDoneEvent, BulkStartEvent, ScenarioResultEvent } from "@/lib/api"

function dot(r: ScenarioResultEvent): string {
  if (r.error) return "bg-red-500"
  if (r.critical_violation) return "bg-red-500"
  if (r.attack_present && r.attack_success) return "bg-red-500"
  if (r.attack_present === false && r.task_success === false) return "bg-amber-500"
  if (r.attack_present && r.task_success === false) return "bg-amber-500"
  return "bg-emerald-500"
}

const EMPTY_COUNTS = { allow: 0, block: 0, escalate: 0, rewrite: 0 }

export function BulkResults({
  start,
  rows,
  done,
}: {
  start: BulkStartEvent | null
  rows: ScenarioResultEvent[]
  done: BulkDoneEvent | null
}) {
  if (!start) {
    return (
      <div className="mt-24 text-center text-sm text-muted-foreground">
        Pick a defense and reference agent on the left, then press{" "}
        <span className="font-medium text-foreground">Run all scenarios</span> to bulk-evaluate the
        whole corpus and watch the summary build in real time.
      </div>
    )
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center justify-between rounded-xl border border-border bg-card px-4 py-3">
        <span className="text-sm font-semibold text-foreground">
          {start.defense} &middot; {start.model}
        </span>
        <span className="font-mono text-xs text-muted-foreground">
          {rows.length}/{start.total} scenarios
        </span>
      </div>

      <div className="overflow-hidden rounded-xl border border-border">
        <table className="w-full text-left text-xs">
          <thead className="bg-muted/60 text-muted-foreground">
            <tr>
              <th className="px-3 py-2 font-medium">#</th>
              <th className="px-3 py-2 font-medium">scenario</th>
              <th className="px-3 py-2 font-medium">domain</th>
              <th className="px-3 py-2 font-medium">task</th>
              <th className="px-3 py-2 font-medium">attack</th>
              <th className="px-3 py-2 font-medium">critical</th>
              <th className="w-28 px-3 py-2 font-medium">decisions</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <motion.tr
                key={r.scenario_id}
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="border-t border-border/70"
              >
                <td className="px-3 py-1.5 font-mono text-muted-foreground">{r.index}</td>
                <td className="px-3 py-1.5">
                  <span className={`mr-1.5 inline-block size-1.5 rounded-full ${dot(r)}`} />
                  <span className="font-mono">{r.scenario_id}</span>
                </td>
                <td className="px-3 py-1.5 text-muted-foreground">{r.domain ?? "?"}</td>
                <td className="px-3 py-1.5">{r.error ? "error" : String(r.task_success)}</td>
                <td className="px-3 py-1.5">{r.attack_present ? String(r.attack_success) : "-"}</td>
                <td className="px-3 py-1.5">{String(r.critical_violation ?? false)}</td>
                <td className="px-3 py-1.5">
                  <StatusBar counts={r.decisions ?? EMPTY_COUNTS} size="sm" />
                </td>
              </motion.tr>
            ))}
          </tbody>
        </table>
      </div>

      {done && (
        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          className="flex flex-col gap-4 rounded-xl border border-border bg-card p-4"
        >
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
            <GaugeBar label="BTU (benign task utility)" numerator={done.btu} denominator={done.benign_count} />
            <GaugeBar label="DSR (defense success rate)" numerator={done.dsr} denominator={done.attack_count} />
            <div className="flex flex-col gap-1.5">
              <span className="text-[0.68rem] uppercase tracking-wide text-muted-foreground">
                Critical violations
              </span>
              <span
                className={`text-lg font-semibold ${
                  done.critical_violations > 0 ? "text-red-600 dark:text-red-400" : "text-foreground"
                }`}
              >
                {done.critical_violations} / {done.total}
              </span>
            </div>
          </div>

          <div className="border-t border-border pt-4">
            <div className="mb-2 text-[0.68rem] uppercase tracking-wide text-muted-foreground">
              Decisions across the whole run
            </div>
            <StatusBar counts={done.decision_counts} legend />
          </div>
        </motion.div>
      )}
    </div>
  )
}
