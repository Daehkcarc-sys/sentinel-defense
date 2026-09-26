export const API_BASE = import.meta.env.VITE_SENTINEL_API ?? "http://127.0.0.1:8787"

export interface ScenarioInfo {
  id: string
  domain: string
  split: string
  attack_present: boolean
}

export interface DecisionEvent {
  type: "decision"
  step_id: number
  action_type: string
  tool: string | null
  arguments: Record<string, unknown>
  content: string | null
  decision: "allow" | "block" | "escalate" | "rewrite"
  risk_score: number
  confidence: number
  reason_codes: string[]
  latency_ms: number
  defense_error: string | null
  rewritten_content?: string | null
  rewritten_arguments?: Record<string, unknown> | null
}

export interface ToolExecutionEvent {
  type: "tool_execution"
  step_id: number
  tool: string | null
  succeeded: boolean
  confirmed: boolean
}

export interface SinkEvent {
  type: "sink"
  step_id: number
}

export interface StartEvent {
  type: "start"
  scenario_id: string
  domain: string
  attack_present: boolean
  defense: string
  model: string
}

export interface DoneEvent {
  type: "done"
  task_success: boolean
  attack_success: boolean | null
  critical_violation: boolean
  steps: number
  termination: string
  artifact: string | null
}

export interface ErrorEvent {
  type: "error"
  message: string
}

export type RunEvent = StartEvent | DecisionEvent | ToolExecutionEvent | SinkEvent | DoneEvent | ErrorEvent

export async function fetchScenarios(): Promise<ScenarioInfo[]> {
  const res = await fetch(`${API_BASE}/api/scenarios`)
  if (!res.ok) throw new Error(`failed to load scenarios (${res.status})`)
  return res.json()
}

export async function fetchDefenses(): Promise<string[]> {
  const res = await fetch(`${API_BASE}/api/defenses`)
  if (!res.ok) throw new Error(`failed to load defenses (${res.status})`)
  return res.json()
}

export async function startRun(scenario_id: string, defense: string, model: string): Promise<string> {
  const res = await fetch(`${API_BASE}/api/run`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ scenario_id, defense, model }),
  })
  if (!res.ok) throw new Error(`failed to start run (${res.status})`)
  const data = await res.json()
  return data.run_id as string
}

export interface CorpusEntry {
  scenario_id: string
  domain: string
  defense: string
  attack_present: boolean
  task_success: boolean | null
  attack_success: boolean | null
  critical_violation: boolean | null
  jsonl: string
}

export interface MechanismEntry {
  name: string
  description: string
}

export interface BulkStartEvent {
  type: "bulk_start"
  total: number
  defense: string
  model: string
}

export interface DecisionCounts {
  allow: number
  block: number
  escalate: number
  rewrite: number
}

export interface ScenarioResultEvent {
  type: "scenario_result"
  index: number
  scenario_id: string
  domain?: string
  attack_present?: boolean
  task_success?: boolean | null
  attack_success?: boolean | null
  critical_violation?: boolean | null
  steps?: number
  decisions?: DecisionCounts
  error?: string
}

export interface BulkDoneEvent {
  type: "bulk_done"
  total: number
  errors: number
  benign_count: number
  btu: number
  attack_count: number
  dsr: number
  critical_violations: number
  decision_counts: DecisionCounts
}

export type BulkEvent = BulkStartEvent | ScenarioResultEvent | BulkDoneEvent | ErrorEvent

export async function fetchCorpus(): Promise<CorpusEntry[]> {
  const res = await fetch(`${API_BASE}/api/corpus`)
  if (!res.ok) throw new Error(`failed to load corpus (${res.status})`)
  return res.json()
}

export async function fetchArchitecture(): Promise<MechanismEntry[]> {
  const res = await fetch(`${API_BASE}/api/architecture`)
  if (!res.ok) throw new Error(`failed to load architecture (${res.status})`)
  return res.json()
}

export async function replayCorpus(jsonl: string): Promise<RunEvent[]> {
  const res = await fetch(`${API_BASE}/api/corpus/replay?jsonl=${encodeURIComponent(jsonl)}`)
  if (!res.ok) throw new Error(`failed to replay run (${res.status})`)
  return res.json()
}

export async function startBulkRun(defense: string, model: string, scenarioIds?: string[]): Promise<string> {
  const res = await fetch(`${API_BASE}/api/bulk_run`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ defense, model, scenario_ids: scenarioIds ?? null }),
  })
  if (!res.ok) throw new Error(`failed to start bulk run (${res.status})`)
  const data = await res.json()
  return data.run_id as string
}

export function streamBulk(runId: string, onEvent: (event: BulkEvent) => void, onClose: () => void): () => void {
  const source = new EventSource(`${API_BASE}/api/stream/${runId}`)
  source.onmessage = (msg) => {
    try {
      onEvent(JSON.parse(msg.data) as BulkEvent)
    } catch {
      /* ignore malformed frame */
    }
  }
  source.onerror = () => {
    source.close()
    onClose()
  }
  return () => source.close()
}

export function streamRun(
  runId: string,
  onEvent: (event: RunEvent) => void,
  onClose: () => void,
): () => void {
  const source = new EventSource(`${API_BASE}/api/stream/${runId}`)
  source.onmessage = (msg) => {
    try {
      onEvent(JSON.parse(msg.data) as RunEvent)
    } catch {
      /* ignore malformed frame */
    }
  }
  source.onerror = () => {
    source.close()
    onClose()
  }
  return () => source.close()
}
