/**
 * Recent-analysis history in browser localStorage.
 *
 * This is per-browser convenience storage, not server-side or multi-user
 * persistence. The stored schema is versioned, and corrupted or outdated data
 * is discarded rather than trusted.
 */

import { useCallback, useEffect, useState } from 'react'
import type { Analysis } from '@/types/api'

const STORAGE_KEY = 'ignite.history.v1'
const SCHEMA_VERSION = 1
const MAX_ENTRIES = 10

export interface HistoryEntry {
  id: string
  description: string
  generated_at: string
  analysis: Analysis
}

interface StoredShape {
  version: number
  entries: HistoryEntry[]
}

function isEntry(value: unknown): value is HistoryEntry {
  if (typeof value !== 'object' || value === null) return false
  const entry = value as Partial<HistoryEntry>
  return (
    typeof entry.id === 'string' &&
    typeof entry.description === 'string' &&
    typeof entry.generated_at === 'string' &&
    typeof entry.analysis === 'object' &&
    entry.analysis !== null
  )
}

/** Read history, discarding anything malformed or from an older schema. */
function read(): HistoryEntry[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (!raw) return []

    const parsed = JSON.parse(raw) as Partial<StoredShape>
    if (parsed.version !== SCHEMA_VERSION || !Array.isArray(parsed.entries)) {
      // Outdated or unrecognised shape: drop it rather than guess.
      localStorage.removeItem(STORAGE_KEY)
      return []
    }
    return parsed.entries.filter(isEntry).slice(0, MAX_ENTRIES)
  } catch {
    // Corrupted JSON or storage unavailable (private mode, blocked cookies).
    try {
      localStorage.removeItem(STORAGE_KEY)
    } catch {
      /* nothing further we can do */
    }
    return []
  }
}

function write(entries: HistoryEntry[]) {
  try {
    const payload: StoredShape = { version: SCHEMA_VERSION, entries: entries.slice(0, MAX_ENTRIES) }
    localStorage.setItem(STORAGE_KEY, JSON.stringify(payload))
  } catch {
    // Quota exceeded or storage blocked: history is best-effort only.
  }
}

export function useHistory() {
  const [entries, setEntries] = useState<HistoryEntry[]>([])

  useEffect(() => {
    setEntries(read())
  }, [])

  const add = useCallback((analysis: Analysis) => {
    setEntries((current) => {
      const entry: HistoryEntry = {
        id: `${analysis.generated_at}-${analysis.description.slice(0, 24)}`,
        description: analysis.description,
        generated_at: analysis.generated_at,
        analysis,
      }
      // Drop any prior entry for the same description so the list stays useful.
      const deduped = current.filter((e) => e.description !== analysis.description)
      const next = [entry, ...deduped].slice(0, MAX_ENTRIES)
      write(next)
      return next
    })
  }, [])

  const clear = useCallback(() => {
    setEntries([])
    try {
      localStorage.removeItem(STORAGE_KEY)
    } catch {
      /* ignore */
    }
  }, [])

  return { entries, add, clear }
}
