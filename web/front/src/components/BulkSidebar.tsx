import { useEffect, useState } from "react"
import { motion } from "motion/react"
import { PlayCircle, Loader2 } from "lucide-react"
import { cn } from "@/lib/utils"
import { fetchDefenses } from "@/lib/api"

interface Props {
  onRun: (defense: string, model: string) => void
  running: boolean
}

const MODELS = [
  { value: "mock", label: "mock (instant, all 62 in seconds)" },
  { value: "ollama:qwen3:8b", label: "ollama:qwen3:8b (real, ~4-5s/scenario)" },
]

export function BulkSidebar({ onRun, running }: Props) {
  const [defenses, setDefenses] = useState<string[]>([])
  const [defense, setDefense] = useState("sentinel_hybrid")
  const [model, setModel] = useState("mock")

  useEffect(() => {
    fetchDefenses().then(setDefenses)
  }, [])

  return (
    <div className="flex h-full flex-col gap-3">
      <p className="text-xs leading-relaxed text-muted-foreground">
        Runs every scenario in the corpus against the real evaluator, sequentially, streaming a result
        row per scenario as it finishes -- then an aggregate BTU / DSR / critical-violation summary.
      </p>
      <div className="flex flex-col gap-1">
        <label className="text-[0.68rem] font-medium uppercase tracking-wide text-muted-foreground">Defense</label>
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
      {model.startsWith("ollama") && (
        <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-2 text-xs text-amber-700 dark:text-amber-400">
          Full corpus on real Qwen3-8B takes several minutes. The table fills in as each scenario
          finishes.
        </div>
      )}
      <div className="mt-auto">
        <motion.button
          whileTap={{ scale: 0.97 }}
          disabled={running}
          onClick={() => onRun(defense, model)}
          className={cn(
            "flex w-full items-center justify-center gap-2 rounded-lg px-3 py-2.5 text-sm font-semibold shadow-sm transition-colors",
            running ? "cursor-wait bg-muted text-muted-foreground" : "bg-primary text-primary-foreground hover:bg-primary/85",
          )}
        >
          {running ? (
            <>
              <Loader2 className="size-4 animate-spin" /> Running corpus...
            </>
          ) : (
            <>
              <PlayCircle className="size-4" /> Run all scenarios
            </>
          )}
        </motion.button>
      </div>
    </div>
  )
}
