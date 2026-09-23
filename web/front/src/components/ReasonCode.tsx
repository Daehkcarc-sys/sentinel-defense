import { useState } from "react"
import reasonCodes from "@/data/reasonCodes.json"

type Entry = [mechanism: string, explanation: string]
const CODES = reasonCodes as unknown as Record<string, Entry>

export function ReasonCode({ code }: { code: string }) {
  const [open, setOpen] = useState(false)
  const entry = CODES[code]
  return (
    <span
      className="relative inline-block"
      onMouseEnter={() => setOpen(true)}
      onMouseLeave={() => setOpen(false)}
      onFocus={() => setOpen(true)}
      onBlur={() => setOpen(false)}
      tabIndex={0}
    >
      <code className="cursor-help rounded border border-border bg-muted px-1.5 py-0.5 text-[0.72rem] text-foreground/80">
        {code}
      </code>
      {open && entry && (
        <span className="absolute bottom-full left-0 z-50 mb-2 w-72 rounded-lg border border-border bg-popover p-3 text-left text-xs leading-relaxed text-popover-foreground shadow-xl">
          <span className="mb-1 block font-semibold text-foreground">{entry[0]}</span>
          <span className="text-muted-foreground">{entry[1]}</span>
        </span>
      )}
    </span>
  )
}
