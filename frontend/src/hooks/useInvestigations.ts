/**
 * Saved investigations, persisted server-side in SQLite.
 *
 * Distinct from `useHistory`, which keeps recent analyses in browser
 * localStorage. Saved investigations survive across browsers and carry a
 * title, notes, the selected rule and any test cases.
 */

import { useCallback, useEffect, useState } from 'react'
import {
  ApiError,
  createInvestigation,
  deleteInvestigation,
  duplicateInvestigation,
  getInvestigation,
  listInvestigations,
  updateInvestigation,
} from '@/lib/api'
import type { InvestigationDetail, InvestigationSummary } from '@/types/api'

export function useInvestigations() {
  const [items, setItems] = useState<InvestigationSummary[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [query, setQuery] = useState('')
  /** Set once an investigation is saved or opened, so Save updates in place. */
  const [currentId, setCurrentId] = useState<string | null>(null)

  const refresh = useCallback(
    async (search = query) => {
      setLoading(true)
      setError(null)
      try {
        setItems(await listInvestigations(search))
      } catch (err) {
        setError(
          err instanceof ApiError ? err.message : 'Saved investigations could not be loaded.',
        )
      } finally {
        setLoading(false)
      }
    },
    [query],
  )

  useEffect(() => {
    void refresh('')
  }, [refresh])

  const save = useCallback(
    async (title: string, notes: string, payload: Record<string, unknown>) => {
      setError(null)
      try {
        // Update in place when this investigation is already saved, so a second
        // save cannot create a duplicate record.
        const record = currentId
          ? await updateInvestigation(currentId, { title, notes, payload })
          : await createInvestigation({ title, notes, payload })
        setCurrentId(record.id)
        await refresh()
        return record
      } catch (err) {
        setError(err instanceof ApiError ? err.message : 'The investigation could not be saved.')
        return null
      }
    },
    [currentId, refresh],
  )

  const open = useCallback(async (id: string): Promise<InvestigationDetail | null> => {
    setError(null)
    try {
      const record = await getInvestigation(id)
      setCurrentId(record.id)
      return record
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'The investigation could not be opened.')
      return null
    }
  }, [])

  const duplicate = useCallback(
    async (id: string) => {
      setError(null)
      try {
        const record = await duplicateInvestigation(id)
        await refresh()
        return record
      } catch (err) {
        setError(err instanceof ApiError ? err.message : 'The copy could not be created.')
        return null
      }
    },
    [refresh],
  )

  const remove = useCallback(
    async (id: string) => {
      setError(null)
      try {
        await deleteInvestigation(id)
        if (currentId === id) setCurrentId(null)
        await refresh()
        return true
      } catch (err) {
        setError(err instanceof ApiError ? err.message : 'The investigation could not be deleted.')
        return false
      }
    },
    [currentId, refresh],
  )

  return {
    items,
    loading,
    error,
    query,
    setQuery,
    refresh,
    save,
    open,
    duplicate,
    remove,
    currentId,
    setCurrentId,
  }
}
