/**
 * AI availability.
 *
 * Checked once on mount and only re-checked when the user explicitly asks, so
 * ordinary renders never probe the model server. The backend additionally
 * caches the probe.
 */

import { useCallback, useEffect, useState } from 'react'
import { getAIStatus } from '@/lib/api'
import type { AIStatus } from '@/types/api'

export type AIPhase = 'unknown' | 'available' | 'unavailable' | 'checking'

export function useAIStatus() {
  const [status, setStatus] = useState<AIStatus | null>(null)
  const [phase, setPhase] = useState<AIPhase>('unknown')

  const check = useCallback(async (refresh = false) => {
    setPhase('checking')
    try {
      const result = await getAIStatus(refresh)
      setStatus(result)
      setPhase(result.available ? 'available' : 'unavailable')
    } catch {
      // The API itself is unreachable; report AI as unavailable rather than
      // leaving the indicator in limbo.
      setStatus(null)
      setPhase('unavailable')
    }
  }, [])

  useEffect(() => {
    void check(false)
  }, [check])

  return { status, phase, check }
}
