import type { ReactNode } from "react"
import { Radio, ListChecks, Database, BookOpen } from "lucide-react"
import { ThemeToggle } from "@/components/ThemeToggle"
import { cn } from "@/lib/utils"

export type Mode = "live" | "bulk" | "corpus" | "architecture"

const TABS: { id: Mode; label: string; icon: typeof Radio }[] = [
  { id: "live", label: "Live run", icon: Radio },
  { id: "bulk", label: "Bulk run", icon: ListChecks },
  { id: "corpus", label: "Evidence corpus", icon: Database },
  { id: "architecture", label: "Architecture", icon: BookOpen },
]

export function NavRail({
  mode,
  onModeChange,
  children,
}: {
  mode: Mode
  onModeChange: (m: Mode) => void
  children: ReactNode
}) {
  return (
    <aside className="flex h-full w-80 shrink-0 flex-col gap-3 border-r border-sidebar-border bg-sidebar p-4 text-sidebar-foreground">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-sm font-semibold tracking-tight text-sidebar-foreground">SENTINEL</h1>
          <p className="text-xs text-muted-foreground">observability &amp; defense demo</p>
        </div>
        <ThemeToggle />
      </div>

      <nav className="grid grid-cols-2 gap-1.5">
        {TABS.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            onClick={() => onModeChange(id)}
            className={cn(
              "flex flex-col items-start gap-1 rounded-lg border px-2.5 py-2 text-left text-xs font-medium transition-colors",
              mode === id
                ? "border-sidebar-primary/40 bg-sidebar-primary text-sidebar-primary-foreground"
                : "border-sidebar-border bg-background/40 text-sidebar-foreground hover:bg-sidebar-accent/60",
            )}
          >
            <Icon className="size-3.5" />
            {label}
          </button>
        ))}
      </nav>

      <div className="min-h-0 flex-1">{children}</div>
    </aside>
  )
}
