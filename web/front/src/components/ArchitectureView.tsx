import { PipelineDiagram } from "@/components/PipelineDiagram"

export function ArchitectureView() {
  return (
    <div className="flex flex-col gap-4">
      <div>
        <h2 className="text-lg font-semibold text-foreground">How the defense works</h2>
        <p className="mt-1 text-sm text-muted-foreground">
          <code className="rounded bg-muted px-1.5 py-0.5">sentinel_hybrid</code> is one deterministic
          decision path -- Authority Core (the hard policy kernel) plus three narrow, falsification-tested
          conjunctions and two self-revalidating repair mechanisms. No weighted voting, no LLM judge in
          the security path.
        </p>
      </div>

      <PipelineDiagram />

      <div className="rounded-xl border border-border bg-card p-4 text-xs leading-relaxed text-muted-foreground">
        <span className="font-semibold text-foreground">Evidence, not assertion:</span> every claim above
        is backed by a falsification test against the real scenario corpus, plus independent re-verification
        on fresh live Qwen3-8B runs where noted in the technical report (Sections 6.5 and 7.10) -- see the
        Evidence corpus and Bulk run tabs for the receipts.
      </div>
    </div>
  )
}
