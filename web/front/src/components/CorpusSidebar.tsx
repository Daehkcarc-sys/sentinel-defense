import { useEffect, useMemo, useState } from "react"
import { cn } from "@/lib/utils"
import { fetchCorpus, type CorpusEntry } from "@/lib/api"

interface Props {
  onSelect: (entry: CorpusEntry) => void
  selected: string | null
}

function statusDot(e: CorpusEntry): string {
  if (e.critical_violation) return "bg-red-500"
  if (e.attack_present && e.attack_success === true) return "bg-red-500"
  if (e.attack_present && e.attack_success === false) return e.task_success ? "bg-emerald-500" : "bg-amber-500"
  return e.task_success ? "bg-emerald-500" : "bg-amber-500"
}

export function CorpusSidebar({ onSelect, selected }: Props) {
  const [entries, setEntries] = useState<CorpusEntry[]>([])
  const [error, setError] = useState<string | null>(null)
  const [defenseFilter, setDefenseFilter] = useState<string>("sentinel_hybrid")

  useEffect(() => {
    fetchCorpus()
      .then(setEntries)
      .catch((e) => setError(String(e)))
  }, [])

  const grouped = useMemo(() => {
    const groups: Record<string, CorpusEntry[]> = {}
    for (const e of entries) {
      if (e.defense !== defenseFilter) continue
      const key = `${e.domain} · ${e.attack_present ? "attack" : "benign"}`
      groups[key] ??= []
      groups[key].push(e)
    }
    return groups
  }, [entries, defenseFilter])

  const defenseOptions = useMemo(() => Array.from(new Set(entries.map((e) => e.defense))), [entries])

  return (
    <div className="flex h-full flex-col gap-3">
      <p className="text-xs leading-relaxed text-muted-foreground">
        Pre-recorded real-Qwen3-8B runs from the full corpus batch (<code>qwen_full_corpus_results.json</code>),
        replayed exactly as captured -- not a fresh run.
      </p>
      {error && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-2 text-xs text-red-600 dark:text-red-400">
          {error}
        </div>
      )}
      <div className="flex flex-col gap-1">
        <label className="text-[0.68rem] font-medium uppercase tracking-wide text-muted-foreground">Defense</label>
        <select
          value={defenseFilter}
          onChange={(e) => setDefenseFilter(e.target.value)}
          className="rounded-lg border border-input bg-background px-2.5 py-1.5 text-sm text-foreground"
        >
          {defenseOptions.map((d) => (
            <option key={d} value={d}>
              {d}
            </option>
          ))}
        </select>
      </div>
      <div className="min-h-0 flex-1 overflow-y-auto rounded-lg border border-sidebar-border">
        {Object.entries(grouped).map(([cat, list]) => (
          <div key={cat}>
            <div className="sticky top-0 bg-sidebar-accent px-2.5 py-1 text-[0.68rem] font-semibold uppercase tracking-wide text-sidebar-accent-foreground">
              {cat}
            </div>
            {list.map((e) => {
              const key = `${e.scenario_id}::${e.defense}`
              return (
                <button
                  key={key}
                  onClick={() => onSelect(e)}
                  className={cn(
                    "flex w-full items-center gap-2 px-2.5 py-1.5 text-left text-xs transition-colors",
                    selected === key
                      ? "bg-sidebar-primary text-sidebar-primary-foreground"
                      : "text-sidebar-foreground hover:bg-sidebar-accent/60",
                  )}
                >
                  <span className={cn("size-1.5 shrink-0 rounded-full", statusDot(e))} />
                  <span className="truncate font-mono">{e.scenario_id}</span>
                </button>
              )
            })}
          </div>
        ))}
      </div>
    </div>
  )
}
