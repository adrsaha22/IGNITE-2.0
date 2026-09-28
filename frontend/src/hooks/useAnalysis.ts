/**
 * Analysis state for the primary generation workflow.
 *
 * Generation goes through the Gemini-backed `/api/rules/generate` endpoint.
 * There is deliberately **no fallback** to the legacy template pipeline: if
 * generation fails, the user is told, and no rules are shown as though the
 * model produced them.
 *
 * Two guarantees this hook enforces:
 *
 * * A stale response can never overwrite a newer one (request sequencing).
 * * A failed attempt clears the previous result rather than leaving old
 *   candidates on screen as if they were the outcome of the latest run.
 */

import { useCallback, useRef, useState } from 'react'
import { ApiError, generateRules } from '@/lib/api'
import { toAnalysis } from '@/lib/generation'
import type { Analysis } from '@/types/api'

export interface AnalysisState {
  analysis: Analysis | null
  /** The description that produced `analysis`. */
  analysedInput: string
  loading: boolean
  error: string | null
  /** Backend failure status (e.g. not_configured, rate_limited), when known. */
  errorStatus: string | null
}

/** Actionable guidance per backend failure status. */
const STATUS_GUIDANCE: Record<string, string> = {
  not_configured:
    'Set GEMINI_API_KEY in the backend environment and restart the API to enable rule generation.',
  unauthorized: 'The configured API key was rejected. Check GEMINI_API_KEY.',
  rate_limited: 'The provider rate limit was reached. Wait a moment and try again.',
  timeout: 'The provider did not respond in time. Try again.',
  unreachable: 'The provider could not be reached. Check network connectivity.',
  provider_error:
    'The provider returned an error. This is often temporary — try again shortly.',
  malformed: 'The model returned output that could not be read. Try again.',
  blocked: 'The provider declined this request. Try rephrasing the scenario.',
  // Demo mode refuses scenarios outside its small template set rather than
  // returning an unrelated rule; the backend message already lists what it
  // covers, so no extra guidance is appended here.
  unsupported_in_demo_mode: '',
}

const INITIAL: AnalysisState = {
  analysis: null,
  analysedInput: '',
  loading: false,
  error: null,
  errorStatus: null,
}

export function useAnalysis(onSuccess?: (analysis: Analysis) => void) {
  const [state, setState] = useState<AnalysisState>(INITIAL)

  // Guards against duplicate submissions while a request is in flight.
  const inFlight = useRef(false)
  // Monotonic request id: only the newest request may write state, so a slow
  // earlier response cannot clobber a newer result.
  const requestSeq = useRef(0)

  const run = useCallback(
    async (description: string) => {
      const trimmed = description.trim()
      if (!trimmed || inFlight.current) return

      inFlight.current = true
      const seq = ++requestSeq.current
      setState((s) => ({ ...s, loading: true, error: null, errorStatus: null }))

      try {
        const result = await generateRules(trimmed)

        // A newer request started while this one was running.
        if (seq !== requestSeq.current) return

        if (!result.ok || result.candidates.length === 0) {
          const guidance = STATUS_GUIDANCE[result.status] ?? ''
          const detail =
            result.message ||
            (result.candidates.length === 0
              ? 'The model returned no detection candidates.'
              : 'Generation failed.')

          // The backend message and our guidance often say the same thing;
          // showing both reads as a stutter, so keep only the added value.
          const combined =
            guidance && !detail.toLowerCase().includes(guidance.slice(0, 24).toLowerCase())
              ? `${detail} ${guidance}`
              : detail

          // Clear the previous analysis: leaving it on screen would present
          // an earlier result as the outcome of this failed attempt.
          setState({
            ...INITIAL,
            error: combined,
            errorStatus: result.status,
          })
          return
        }

        const analysis = toAnalysis(trimmed, result)
        setState({
          analysis,
          analysedInput: trimmed,
          loading: false,
          error: null,
          errorStatus: null,
        })
        onSuccess?.(analysis)
      } catch (err) {
        if (seq !== requestSeq.current) return

        const message =
          err instanceof ApiError
            ? err.message
            : 'Detection rule generation could not be completed.'
        setState({ ...INITIAL, error: message, errorStatus: 'request_failed' })
      } finally {
        if (seq === requestSeq.current) inFlight.current = false
      }
    },
    [onSuccess],
  )

  const restore = useCallback((analysis: Analysis) => {
    // Restoring a saved investigation supersedes any in-flight request.
    requestSeq.current += 1
    inFlight.current = false
    setState({
      analysis,
      analysedInput: analysis.description,
      loading: false,
      error: null,
      errorStatus: null,
    })
  }, [])

  const reset = useCallback(() => {
    // Invalidate any in-flight request so its response cannot repopulate the
    // workspace the user just cleared.
    requestSeq.current += 1
    inFlight.current = false
    setState(INITIAL)
  }, [])

  const dismissError = useCallback(() => {
    setState((s) => ({ ...s, error: null, errorStatus: null }))
  }, [])

  return { ...state, run, restore, reset, dismissError }
}

/** Whether the editor text has diverged from the analysed input. */
export function isStale(analysedInput: string, current: string): boolean {
  if (!analysedInput) return false
  return analysedInput.trim() !== current.trim()
}
