import { useEffect, useMemo, useState } from "react"
import { motion } from "motion/react"
import { Play, Loader2 } from "lucide-react"
import { cn } from "@/lib/utils"
import { fetchDefenses, fetchScenarios, type ScenarioInfo } from "@/lib/api"

interface Props {
  onRun: (scenarioId: string, defense: string, model: string) => void
  running: boolean
  selectedScenario: string | null
}

const MODELS = [
  { value: "mock", label: "mock (instant, scripted)" },
  { value: "ollama:qwen3:8b", label: "ollama:qwen3:8b (real, quantized)" },
]

export function RunSidebar({ onRun, running, selectedScenario }: Props) {
  const [scenarios, setScenarios] = useState<ScenarioInfo[]>([])
  const [defenses, setDefenses] = useState<string[]>([])
  const [scenarioId, setScenarioId] = useState<string>("")
  const [defense, setDefense] = useState("sentinel_hybrid")
  const [model, setModel] = useState("mock")
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    fetchScenarios()
      .then((list) => {
        setScenarios(list)
        if (list.length) setScenarioId(list[0].id)
      })
      .catch((e) => setError(String(e)))
    fetchDefenses()
      .then(setDefenses)
      .catch((e) => setError(String(e)))
  }, [])

  const grouped = useMemo(() => {
    const groups: Record<string, ScenarioInfo[]> = {}
    for (const s of scenarios) {
      groups[s.domain] ??= []
      groups[s.domain].push(s)
    }
    return groups
  }, [scenarios])

  return (
    <div className="flex h-full flex-col gap-3">
      {error && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-2 text-xs text-red-600 dark:text-red-400">
          {error} -- is <code>uv run python scripts/live_run_server.py</code> running?
        </div>
      )}

      <div className="flex flex-col gap-1">
        <label className="text-[0.68rem] font-medium uppercase tracking-wide text-muted-foreground">
          Defense
        </label>
        <select
          value={defense}
          onChange={(e) => setDefense(e.target.value)}
          className="rounded-lg border border-input bg-background px-2.5 py-1.5 text-sm text-foreground"
        >
          {defenses.map((d) => (
            <option key={d} value={d}>
              {d}
            </option>
          ))}
        </select>
      </div>

      <div className="flex flex-col gap-1">
        <label className="text-[0.68rem] font-medium uppercase tracking-wide text-muted-foreground">
          Reference agent
        </label>
        <select
          value={model}
          onChange={(e) => setModel(e.target.value)}
          className="rounded-lg border border-input bg-background px-2.5 py-1.5 text-sm text-foreground"
        >
          {MODELS.map((m) => (
            <option key={m.value} value={m.value}>
              {m.label}
            </option>
          ))}
        </select>
      </div>

      <div className="flex min-h-0 flex-1 flex-col gap-1">
        <label className="text-[0.68rem] font-medium uppercase tracking-wide text-muted-foreground">
          Scenario
        </label>
        <div className="min-h-0 flex-1 overflow-y-auto rounded-lg border border-sidebar-border">
          {Object.entries(grouped).map(([domain, list]) => (
            <div key={domain}>
              <div className="sticky top-0 bg-sidebar-accent px-2.5 py-1 text-[0.68rem] font-semibold uppercase tracking-wide text-sidebar-accent-foreground">
                {domain}
              </div>
              {list.map((s) => (
                <button
                  key={s.id}
                  onClick={() => setScenarioId(s.id)}
                  className={cn(
                    "flex w-full items-center gap-2 px-2.5 py-1.5 text-left text-xs transition-colors",
                    scenarioId === s.id
                      ? "bg-sidebar-primary text-sidebar-primary-foreground"
                      : "text-sidebar-foreground hover:bg-sidebar-accent/60",
                  )}
                >
                  <span
                    className={cn(
                      "size-1.5 shrink-0 rounded-full",
                      s.attack_present ? "bg-red-500" : "bg-emerald-500",
                    )}
                  />
                  <span className="truncate font-mono">{s.id}</span>
                </button>
              ))}
            </div>
          ))}
        </div>
      </div>

      <motion.button
        whileTap={{ scale: 0.97 }}
        disabled={!scenarioId || running}
        onClick={() => onRun(scenarioId, defense, model)}
        className={cn(
          "flex items-center justify-center gap-2 rounded-lg px-3 py-2.5 text-sm font-semibold shadow-sm transition-colors",
          running
            ? "cursor-wait bg-muted text-muted-foreground"
            : "bg-primary text-primary-foreground hover:bg-primary/85",
        )}
      >
        {running ? (
          <>
            <Loader2 className="size-4 animate-spin" />
            Running{selectedScenario ? ` ${selectedScenario}` : ""}...
          </>
        ) : (
          <>
            <Play className="size-4" />
            Run live
          </>
        )}
      </motion.button>
    </div>
  )
}
