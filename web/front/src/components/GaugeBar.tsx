export function GaugeBar({ label, numerator, denominator }: { label: string; numerator: number; denominator: number }) {
  const pct = denominator > 0 ? (numerator / denominator) * 100 : 0
  return (
    <div className="flex flex-col gap-1.5">
      <div className="flex items-baseline justify-between">
        <span className="text-[0.68rem] uppercase tracking-wide text-muted-foreground">{label}</span>
        <span className="font-mono text-sm font-semibold text-foreground">
          {numerator}/{denominator}
        </span>
      </div>
      <div className="h-2.5 w-full overflow-hidden rounded-full bg-muted">
        <div
          className="h-full rounded-full bg-foreground/70 transition-[width] duration-500 ease-out"
          style={{ width: `${pct}%` }}
        />
      </div>
    </div>
  )
}
