import { useRef, useState } from "react"
import { motion, AnimatePresence } from "motion/react"
import { useGSAP } from "@gsap/react"
import gsap from "gsap"
import { CheckCircle2, Ban, AlertTriangle, Wand2, ChevronDown } from "lucide-react"

const LAYER1 = [
  { title: "Structural tool authorization", desc: "Is this tool in the task's declared allowed-tools set?" },
  { title: "Confirmation requirement", desc: "Consequential actions need a prior human confirmation on record." },
  {
    title: "Destination-independent RESTRICTED check",
    desc: "A RESTRICTED-sensitivity value is never disclosed to ANY destination, including the agent's own final reply.",
  },
  { title: "Authorization-consumption binding", desc: "An exact action can't be silently re-executed once it already ran." },
  {
    title: "Evidence-fidelity tiering",
    desc: "A value sourced only from untrusted content is flagged -- more seriously if it parameterizes a consequential action.",
  },
  {
    title: "Goal-declared object consistency",
    desc: "Can't retarget an object (an alert id, a case id) that the user's own request never named.",
  },
]

const BLOCK_RULES = [
  {
    title: "Untrusted control selector",
    desc: "An operational selector (e.g. which action to take) supported ONLY by untrusted evidence.",
  },
  {
    title: "Untrusted operational expansion",
    desc: "An untrusted object expansion combined with a workflow disposition that requires review.",
  },
  {
    title: "Attacker-selected sensitive sink",
    desc: "Sensitive-data lineage flowing to a destination itself selected only by untrusted content.",
  },
]

const REPAIRS = [
  {
    title: "Restricted-response redaction",
    desc: "If Layer 1 would BLOCK a final response purely for one recognized RESTRICTED value, redact just that value and re-validate the rewritten response through the FULL pipeline again.",
  },
  {
    title: "Grounded control repair",
    desc: "If a closed-vocabulary control parameter is attacker-only, replace it with the one alternative grounded in trusted/runtime evidence -- only if exactly one exists, else no guess.",
  },
]

const OUTPUTS = [
  { key: "allow", label: "Allow", Icon: CheckCircle2, className: "border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-400", desc: "No rule matched -- proceed to tool execution." },
  { key: "escalate", label: "Escalate", Icon: AlertTriangle, className: "border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-400", desc: "Ask a human -- confirmation on record required." },
  { key: "rewrite", label: "Rewrite", Icon: Wand2, className: "border-sky-500/40 bg-sky-500/10 text-sky-700 dark:text-sky-400", desc: "Repair-and-recheck -- loops back through the full pipeline before release." },
  { key: "block", label: "Block", Icon: Ban, className: "border-red-500/40 bg-red-500/10 text-red-700 dark:text-red-400", desc: "Layer 1 or Layer 2 conjunction-gated rule fired -- no tool execution." },
]

function ExpandableCard({ title, desc, accent }: { title: string; desc: string; accent: string }) {
  const [open, setOpen] = useState(false)
  return (
    <motion.button
      layout
      onClick={() => setOpen((o) => !o)}
      whileHover={{ y: -2 }}
      whileTap={{ scale: 0.98 }}
      className={`w-full rounded-lg border ${accent} bg-card/60 p-3 text-left transition-colors`}
    >
      <div className="flex items-center justify-between gap-2">
        <span className="text-xs font-semibold text-foreground">{title}</span>
        <motion.span animate={{ rotate: open ? 180 : 0 }} transition={{ duration: 0.2 }}>
          <ChevronDown className="size-3.5 text-muted-foreground" />
        </motion.span>
      </div>
      <AnimatePresence initial={false}>
        {open && (
          <motion.p
            initial={{ height: 0, opacity: 0, marginTop: 0 }}
            animate={{ height: "auto", opacity: 1, marginTop: 8 }}
            exit={{ height: 0, opacity: 0, marginTop: 0 }}
            className="overflow-hidden text-[0.72rem] leading-relaxed text-muted-foreground"
          >
            {desc}
          </motion.p>
        )}
      </AnimatePresence>
    </motion.button>
  )
}

const fadeUp = {
  hidden: { opacity: 0, y: 16 },
  show: { opacity: 1, y: 0 },
}

export function PipelineDiagram() {
  const loopRef = useRef<SVGPathElement>(null)

  useGSAP(() => {
    if (!loopRef.current) return
    const len = loopRef.current.getTotalLength()
    gsap.set(loopRef.current, { strokeDasharray: `${len * 0.12} ${len * 0.05}` })
    gsap.to(loopRef.current, { strokeDashoffset: -len, duration: 3.5, repeat: -1, ease: "none" })
  }, [])

  return (
    <motion.div
      initial="hidden"
      animate="show"
      variants={{ show: { transition: { staggerChildren: 0.12 } } }}
      className="flex flex-col gap-3"
    >
      <p className="text-xs text-muted-foreground">
        Click any box to expand it. This is the live pipeline, not a picture of it -- every stage below
        is real, hover/click-driven content.
      </p>

      <motion.div variants={fadeUp} className="rounded-lg border border-border bg-card px-4 py-2.5 text-center text-sm font-semibold text-foreground">
        Agent proposes candidate action
      </motion.div>

      <motion.div variants={fadeUp} className="rounded-lg border border-border bg-muted/50 px-4 py-2.5 text-center text-xs text-muted-foreground">
        <span className="font-semibold text-foreground">Canonical provenance / source index</span> -- trust level,
        sensitivity, source type and provenance id resolved once; both layers below read the same index.
      </motion.div>

      <motion.div variants={fadeUp} className="relative rounded-xl border-2 border-foreground/20 bg-background/40 p-4">
        <div className="mb-3 text-xs font-semibold text-foreground">
          Defense.decide() <span className="font-normal text-muted-foreground">-- single deterministic path, no voting ensemble, no LLM judge</span>
        </div>

        <div className="mb-2 rounded-lg border border-sky-500/30 bg-sky-500/5 p-3">
          <div className="mb-2 text-[0.72rem] font-bold uppercase tracking-wide text-sky-700 dark:text-sky-400">
            Layer 1 -- Authority Core (authority_core_v3_full, unchanged)
          </div>
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
            {LAYER1.map((item) => (
              <ExpandableCard key={item.title} title={item.title} desc={item.desc} accent="border-sky-500/25" />
            ))}
          </div>
        </div>

        <div className="my-2 text-center text-[0.68rem] italic text-muted-foreground">
          layered on top -- reads the same index -- cannot override or weaken Layer 1
        </div>

        <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/5 p-3">
          <div className="mb-2 text-[0.72rem] font-bold uppercase tracking-wide text-emerald-700 dark:text-emerald-400">
            Layer 2 -- sentinel_hybrid additions (narrow, conjunction-gated -- production path)
          </div>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <div>
              <div className="mb-1.5 text-[0.68rem] font-semibold text-muted-foreground">
                Conjunction-gated BLOCK rules
              </div>
              <div className="flex flex-col gap-1.5">
                {BLOCK_RULES.map((item) => (
                  <ExpandableCard key={item.title} title={item.title} desc={item.desc} accent="border-emerald-500/25" />
                ))}
              </div>
            </div>
            <div>
              <div className="mb-1.5 text-[0.68rem] font-semibold text-muted-foreground">
                Self-revalidating REPAIR mechanisms
              </div>
              <div className="flex flex-col gap-1.5">
                {REPAIRS.map((item) => (
                  <ExpandableCard key={item.title} title={item.title} desc={item.desc} accent="border-emerald-500/25" />
                ))}
              </div>
            </div>
          </div>
        </div>
      </motion.div>

      <motion.div variants={fadeUp} className="relative grid grid-cols-2 gap-2 sm:grid-cols-4">
        {OUTPUTS.map(({ key, label, Icon, className, desc }) => (
          <motion.div
            key={key}
            whileHover={{ y: -3, scale: 1.02 }}
            className={`rounded-lg border p-3 text-center ${className}`}
          >
            <Icon className="mx-auto mb-1 size-4" />
            <div className="text-xs font-bold">{label}</div>
            <div className="mt-1 text-[0.65rem] leading-snug opacity-80">{desc}</div>
          </motion.div>
        ))}

        <svg className="pointer-events-none absolute -right-2 -top-16 h-20 w-16 overflow-visible" viewBox="0 0 60 80">
          <path
            ref={loopRef}
            d="M 45 75 C 60 55, 60 20, 40 5"
            fill="none"
            stroke="rgb(14 165 233)"
            strokeWidth="2"
            strokeLinecap="round"
          />
        </svg>
      </motion.div>
      <motion.p variants={fadeUp} className="text-center text-[0.68rem] italic text-muted-foreground">
        REWRITE is not a bypass: the repaired candidate re-enters Defense.decide() and is re-validated
        through the full pipeline (animated loop above) before it can be released.
      </motion.p>

      <motion.div variants={fadeUp} className="rounded-lg border border-border bg-card px-4 py-2.5 text-center text-xs text-muted-foreground">
        <span className="font-semibold text-foreground">Observability trace (JSONL)</span> -- every decision is
        logged with rationale, matched rule(s), and provenance references; REWRITE is logged both as issued and
        after final resolution.
      </motion.div>
    </motion.div>
  )
}
