import { useEffect, useState } from "react"
import { motion } from "motion/react"
import { Moon, Sun, NotebookText } from "lucide-react"
import { applyTheme, getStoredTheme, nextTheme, type Theme } from "@/lib/theme"

const ICONS: Record<Theme, React.ComponentType<{ className?: string }>> = {
  dark: Moon,
  light: Sun,
  notebook: NotebookText,
}

export function ThemeToggle() {
  const [theme, setTheme] = useState<Theme>("dark")

  useEffect(() => {
    const stored = getStoredTheme()
    setTheme(stored)
    applyTheme(stored)
  }, [])

  const Icon = ICONS[theme]

  return (
    <motion.button
      whileTap={{ scale: 0.9 }}
      whileHover={{ scale: 1.05 }}
      onClick={() => {
        const next = nextTheme(theme)
        setTheme(next)
        applyTheme(next)
      }}
      className="inline-flex items-center gap-1.5 rounded-lg border border-border bg-background px-2.5 py-1.5 text-xs font-medium text-foreground hover:bg-muted"
      aria-label="Cycle theme"
    >
      <motion.span
        key={theme}
        initial={{ rotate: -90, opacity: 0 }}
        animate={{ rotate: 0, opacity: 1 }}
        transition={{ duration: 0.25 }}
        className="inline-flex"
      >
        <Icon className="size-3.5" />
      </motion.span>
      <span className="capitalize">{theme}</span>
    </motion.button>
  )
}
