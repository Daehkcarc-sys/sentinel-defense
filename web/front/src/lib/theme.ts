export type Theme = "dark" | "light" | "notebook"

const THEMES: Theme[] = ["dark", "light", "notebook"]
const KEY = "sentinel-dashboard-theme"

export function getStoredTheme(): Theme {
  try {
    const v = localStorage.getItem(KEY)
    if (v === "dark" || v === "light" || v === "notebook") return v
  } catch {
    /* ignore */
  }
  return "dark"
}

export function applyTheme(theme: Theme) {
  const root = document.documentElement
  root.classList.toggle("dark", theme === "dark")
  if (theme === "notebook") {
    root.setAttribute("data-theme", "notebook")
  } else {
    root.removeAttribute("data-theme")
  }
  try {
    localStorage.setItem(KEY, theme)
  } catch {
    /* ignore */
  }
}

export function nextTheme(current: Theme): Theme {
  const i = THEMES.indexOf(current)
  return THEMES[(i + 1) % THEMES.length]
}
