/**
 * The active AI provider and the choices available, shared by the header
 * switcher and the Platform page so both always agree.
 */

import { useCallback, useEffect, useState } from 'react'
import { ApiError, getAIProviders, resetAIProvider, setAIProvider } from '@/lib/api'
import type { AIChoice, AIProviders } from '@/types/api'

export function useAIProviders() {
  const [data, setData] = useState<AIProviders | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const refresh = useCallback(async () => {
    try {
      setData(await getAIProviders())
      setError(null)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'AI providers could not be loaded.')
    }
  }, [])

  useEffect(() => {
    void refresh()
  }, [refresh])

  const run = useCallback(async (action: () => Promise<AIProviders>) => {
    setBusy(true)
    try {
      const next = await action()
      setData(next)
      setError(null)
      return next
    } catch (err) {
      const message = err instanceof ApiError ? err.message : 'The AI provider could not be changed.'
      setError(message)
      throw new Error(message)
    } finally {
      setBusy(false)
    }
  }, [])

  const choose = useCallback((provider: AIChoice) => run(() => setAIProvider(provider)), [run])
  const reset = useCallback(() => run(resetAIProvider), [run])

  return { data, busy, error, refresh, choose, reset }
}

export type AIProvidersState = ReturnType<typeof useAIProviders>
