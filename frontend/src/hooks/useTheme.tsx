/**
 * Theme management: Dark / Light / System.
 *
 * An explicit choice is persisted to localStorage; "system" follows the OS and
 * updates live. The resolved theme is written to <html data-theme>, which is
 * what the CSS variables key off.
 *
 * The initial value is applied by an inline script in index.html before React
 * hydrates, so there is no flash of the wrong theme on load. This provider
 * reads that already-applied value rather than re-deriving it.
 */

import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react'

export type ThemePreference = 'dark' | 'light' | 'system'
export type ResolvedTheme = 'dark' | 'light'

const STORAGE_KEY = 'ignite.theme'

interface ThemeContextValue {
  preference: ThemePreference
  resolved: ResolvedTheme
  setPreference: (preference: ThemePreference) => void
}

const ThemeContext = createContext<ThemeContextValue>({
  preference: 'system',
  resolved: 'dark',
  setPreference: () => {},
})

export function useTheme() {
  return useContext(ThemeContext)
}

function readStoredPreference(): ThemePreference {
  try {
    const stored = localStorage.getItem(STORAGE_KEY)
    if (stored === 'dark' || stored === 'light' || stored === 'system') return stored
  } catch {
    // Storage blocked (private mode); fall through to the default.
  }
  return 'system'
}

function systemTheme(): ResolvedTheme {
  try {
    return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark'
  } catch {
    return 'dark'
  }
}

function apply(resolved: ResolvedTheme) {
  document.documentElement.dataset.theme = resolved
}

export function ThemeProvider({ children }: { children: React.ReactNode }) {
  const [preference, setPreferenceState] = useState<ThemePreference>(readStoredPreference)
  const [systemResolved, setSystemResolved] = useState<ResolvedTheme>(systemTheme)

  // Track OS changes so "system" stays live without a reload.
  useEffect(() => {
    let media: MediaQueryList
    try {
      media = window.matchMedia('(prefers-color-scheme: light)')
    } catch {
      return
    }
    const onChange = (event: MediaQueryListEvent) => {
      setSystemResolved(event.matches ? 'light' : 'dark')
    }
    media.addEventListener('change', onChange)
    return () => media.removeEventListener('change', onChange)
  }, [])

  const resolved: ResolvedTheme = preference === 'system' ? systemResolved : preference

  useEffect(() => {
    apply(resolved)
  }, [resolved])

  const setPreference = useCallback((next: ThemePreference) => {
    setPreferenceState(next)
    try {
      if (next === 'system') {
        // Remove the key so the pre-hydration script falls back to the OS.
        localStorage.removeItem(STORAGE_KEY)
      } else {
        localStorage.setItem(STORAGE_KEY, next)
      }
    } catch {
      // Persistence is best-effort; the in-memory preference still applies.
    }
  }, [])

  const value = useMemo(
    () => ({ preference, resolved, setPreference }),
    [preference, resolved, setPreference],
  )

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>
}
