import { useCallback, useRef, useState } from "react"
import { AnimatePresence, motion } from "motion/react"
import { NavRail, type Mode } from "@/components/NavRail"
import { RunSidebar } from "@/components/RunSidebar"
import { CorpusSidebar } from "@/components/CorpusSidebar"
import { BulkSidebar } from "@/components/BulkSidebar"
import { BulkResults } from "@/components/BulkResults"
import { VerifiedResults } from "@/components/VerifiedResults"
import { ArchitectureView } from "@/components/ArchitectureView"
import { DecisionCard } from "@/components/DecisionCard"
import { OutcomeBanner } from "@/components/OutcomeBanner"
import {
  startRun,
  streamRun,
  startBulkRun,
  streamBulk,
  replayCorpus,
  type CorpusEntry,
  type DecisionEvent,
  type DoneEvent,
  type StartEvent,
  type ToolExecutionEvent,
  type BulkStartEvent,
  type ScenarioResultEvent,
  type BulkDoneEvent,
  type DecisionCounts,
} from "@/lib/api"

type FeedItem = DecisionEvent | ToolExecutionEvent

function decisionCounts(feed: FeedItem[]): DecisionCounts {
  const counts: DecisionCounts = { allow: 0, block: 0, escalate: 0, rewrite: 0 }
  for (const item of feed) {
    if (item.type === "decision" && item.decision in counts) {
      counts[item.decision as keyof DecisionCounts] += 1
    }
  }
  return counts
}

function LiveOrCorpusFeed({
  start,
  feed,
  outcome,
  runError,
  emptyHint,
}: {
  start: StartEvent | null
  feed: FeedItem[]
  outcome: DoneEvent | null
  runError: string | null
  emptyHint: string
}) {
  return (
    <div className="mx-auto flex max-w-3xl flex-col gap-4 px-6 py-8">
      {!start && !runError && <div className="mt-24 text-center text-sm text-muted-foreground">{emptyHint}</div>}

      {start && (
        <motion.div
          initial={{ opacity: 0, y: -8 }}
          animate={{ opacity: 1, y: 0 }}
          className="flex flex-wrap items-center gap-2 rounded-xl border border-border bg-card px-4 py-3"
        >
          <span className="font-mono text-sm font-semibold text-foreground">{start.scenario_id}</span>
          <span className="text-xs text-muted-foreground">{start.domain}</span>
          <span className="ml-auto rounded-md bg-muted px-2 py-0.5 text-xs font-medium text-muted-foreground">
            {start.defense}
          </span>
          <span className="rounded-md bg-muted px-2 py-0.5 text-xs font-medium text-muted-foreground">
            {start.model}
          </span>
          {start.attack_present && (
            <span className="rounded-md bg-red-500/15 px-2 py-0.5 text-xs font-medium text-red-600 dark:text-red-400">
              attack scenario
            </span>
          )}
        </motion.div>
      )}

      {runError && (
        <div className="rounded-xl border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-600 dark:text-red-400">
          {runError}
        </div>
      )}

      <AnimatePresence initial={false}>
        {feed.map((event, i) =>
          event.type === "decision" ? (
            <DecisionCard key={`${event.step_id}-${i}`} event={event} index={i} />
          ) : (
            <motion.div
              key={`${event.step_id}-${i}-exec`}
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="flex items-center gap-2 pl-2 text-xs text-muted-foreground"
            >
              <span className="size-1 rounded-full bg-muted-foreground" />
              {event.tool} executed &middot; {event.succeeded ? "succeeded" : "failed"}
              {event.confirmed ? " (human-confirmed)" : ""}
            </motion.div>
          ),
        )}
      </AnimatePresence>

      {outcome && <OutcomeBanner outcome={outcome} decisions={decisionCounts(feed)} />}
    </div>
  )
}

function App() {
  const [mode, setMode] = useState<Mode>("live")

  // live run state
  const [running, setRunning] = useState(false)
  const [start, setStart] = useState<StartEvent | null>(null)
  const [feed, setFeed] = useState<FeedItem[]>([])
  const [outcome, setOutcome] = useState<DoneEvent | null>(null)
  const [runError, setRunError] = useState<string | null>(null)
  const closeRef = useRef<() => void>(() => {})

  // corpus replay state
  const [corpusSelected, setCorpusSelected] = useState<string | null>(null)
  const [corpusStart, setCorpusStart] = useState<StartEvent | null>(null)
  const [corpusFeed, setCorpusFeed] = useState<FeedItem[]>([])
  const [corpusOutcome, setCorpusOutcome] = useState<DoneEvent | null>(null)
  const [corpusError, setCorpusError] = useState<string | null>(null)

  // bulk run state
  const [bulkRunning, setBulkRunning] = useState(false)
  const [bulkStart, setBulkStart] = useState<BulkStartEvent | null>(null)
  const [bulkRows, setBulkRows] = useState<ScenarioResultEvent[]>([])
  const [bulkDone, setBulkDone] = useState<BulkDoneEvent | null>(null)
  const bulkCloseRef = useRef<() => void>(() => {})

  const handleRun = useCallback(async (scenarioId: string, defense: string, model: string) => {
    closeRef.current()
    setRunning(true)
    setStart(null)
    setFeed([])
    setOutcome(null)
    setRunError(null)
    try {
      const runId = await startRun(scenarioId, defense, model)
      closeRef.current = streamRun(
        runId,
        (event) => {
          if (event.type === "start") setStart(event)
          else if (event.type === "decision" || event.type === "tool_execution") setFeed((f) => [...f, event])
          else if (event.type === "done") {
            setOutcome(event)
            setRunning(false)
          } else if (event.type === "error") {
            setRunError(event.message)
            setRunning(false)
          }
        },
        () => setRunning(false),
      )
    } catch (e) {
      setRunError(String(e))
      setRunning(false)
    }
  }, [])

  const handleCorpusSelect = useCallback(async (entry: CorpusEntry) => {
    setCorpusSelected(`${entry.scenario_id}::${entry.defense}`)
    setCorpusStart(null)
    setCorpusFeed([])
    setCorpusOutcome(null)
    setCorpusError(null)
    try {
      const events = await replayCorpus(entry.jsonl)
      for (const event of events) {
        if (event.type === "start") setCorpusStart(event)
        else if (event.type === "decision" || event.type === "tool_execution")
          setCorpusFeed((f) => [...f, event])
        else if (event.type === "done") setCorpusOutcome(event)
      }
    } catch (e) {
      setCorpusError(String(e))
    }
  }, [])

  const handleBulkRun = useCallback(async (defense: string, model: string) => {
    bulkCloseRef.current()
    setBulkRunning(true)
    setBulkStart(null)
    setBulkRows([])
    setBulkDone(null)
    try {
      const runId = await startBulkRun(defense, model)
      bulkCloseRef.current = streamBulk(
        runId,
        (event) => {
          if (event.type === "bulk_start") setBulkStart(event)
          else if (event.type === "scenario_result") setBulkRows((r) => [...r, event])
          else if (event.type === "bulk_done") {
            setBulkDone(event)
            setBulkRunning(false)
          } else if (event.type === "error") {
            setBulkRunning(false)
          }
        },
        () => setBulkRunning(false),
      )
    } catch {
      setBulkRunning(false)
    }
  }, [])

  return (
    <div className="flex h-screen w-full overflow-hidden bg-background text-foreground">
      <NavRail mode={mode} onModeChange={setMode}>
        {mode === "live" && (
          <RunSidebar onRun={handleRun} running={running} selectedScenario={start?.scenario_id ?? null} />
        )}
        {mode === "corpus" && <CorpusSidebar onSelect={handleCorpusSelect} selected={corpusSelected} />}
        {mode === "bulk" && <BulkSidebar onRun={handleBulkRun} running={bulkRunning} />}
        {mode === "architecture" && (
          <p className="text-xs leading-relaxed text-muted-foreground">
            A jury-facing summary of every mechanism in the shipped defense, in plain language, cross-linked
            to the technical report.
          </p>
        )}
      </NavRail>

      <main className="flex-1 overflow-y-auto">
        {mode === "live" && (
          <LiveOrCorpusFeed
            start={start}
            feed={feed}
            outcome={outcome}
            runError={runError}
            emptyHint="Pick a scenario, defense, and reference agent on the left, then press Run live. Decisions stream in as the defense makes them -- against the real Qwen3-8B reference agent if you choose it, not a pre-recorded replay."
          />
        )}
        {mode === "corpus" && (
          <LiveOrCorpusFeed
            start={corpusStart}
            feed={corpusFeed}
            outcome={corpusOutcome}
            runError={corpusError}
            emptyHint="Pick a pre-recorded real-Qwen3-8B run from the left to replay its exact decision trace."
          />
        )}
        {mode === "bulk" && (
          <div className="mx-auto flex max-w-4xl flex-col gap-4 px-6 py-8">
            <VerifiedResults />
            <BulkResults start={bulkStart} rows={bulkRows} done={bulkDone} />
          </div>
        )}
        {mode === "architecture" && (
          <div className="mx-auto max-w-4xl px-6 py-8">
            <ArchitectureView />
          </div>
        )}
      </main>
    </div>
  )
}

export default App
