import { useState } from 'react'
import { Bot, Loader2, RefreshCw, TriangleAlert } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Disclosure, EmptyState, Panel, PanelHeader } from '@/components/ui/primitives'
import { ApiError, aiAnalyze } from '@/lib/api'
import type { AIPhase } from '@/hooks/useAIStatus'
import type { AIResult } from '@/types/api'

/**
 * Optional LLM summary.
 *
 * Fully independent of rule generation: a model outage produces a concise
 * non-blocking warning here and nothing else in the app is affected. Output is
 * never fabricated or substituted with canned text.
 */
export function AIPanel({
  description,
  phase,
  onRecheck,
}: {
  description: string
  phase: AIPhase
  onRecheck: () => void
}) {
  const [result, setResult] = useState<AIResult | null>(null)
  const [resultFor, setResultFor] = useState('')
  const [loading, setLoading] = useState(false)

  const empty = description.trim().length === 0
  const stale = result !== null && resultFor.trim() !== description.trim()

  async function run() {
    if (empty || loading) return
    setLoading(true)
    try {
      const response = await aiAnalyze(description.trim())
      setResult(response)
      setResultFor(description.trim())
    } catch (err) {
      setResult({
        available: false,
        text: null,
        error:
          err instanceof ApiError ? err.message : 'The AI analysis request could not be completed.',
      })
      setResultFor(description.trim())
    } finally {
      setLoading(false)
    }
  }

  return (
    <Panel>
      <PanelHeader
        title="AI analysis"
        description="Optional language-model summary. Detection rule generation does not depend on it."
        icon={<Bot className="size-4" />}
        actions={
          // Wraps rather than overflowing on narrow viewports.
          <div className="flex flex-wrap items-center gap-2">
            {phase === 'unavailable' && (
              <Button variant="ghost" size="sm" onClick={onRecheck}>
                <RefreshCw />
                Check connection
              </Button>
            )}
            <Button variant="outline" size="sm" onClick={run} disabled={empty || loading}>
              {loading ? <Loader2 className="animate-spin" /> : <Bot />}
              {loading ? 'Requesting…' : 'Run AI analysis'}
            </Button>
          </div>
        }
      />

      <div className="p-4">
        {empty && <EmptyState message="Enter an attack description to request an AI summary." />}

        {!empty && !result && !loading && (
          <EmptyState
            message={
              phase === 'unavailable'
                ? 'The language model is currently unreachable. Rule generation is unaffected.'
                : 'No AI summary requested yet for this description.'
            }
          />
        )}

        {loading && (
          <div className="flex items-center gap-2 text-xs text-ink-muted">
            <Loader2 className="size-3.5 animate-spin text-primary-bright" />
            Waiting for the language model…
          </div>
        )}

        {result && !loading && (
          <div className="space-y-3">
            {stale && (
              <p className="text-[0.7rem] text-ink-faint italic">
                This summary was generated from an earlier description.
              </p>
            )}

            {result.available && result.text ? (
              <div className="rounded-md border border-line bg-canvas px-3.5 py-3 text-xs leading-relaxed whitespace-pre-wrap text-ink">
                {result.text}
              </div>
            ) : (
              <>
                <div className="flex items-start gap-2.5 rounded-md border border-warn/30 bg-warn-soft px-3 py-2.5">
                  <TriangleAlert className="mt-0.5 size-4 shrink-0 text-warn" />
                  <p className="text-xs leading-relaxed text-warn">
                    AI analysis is unavailable — the language model could not be reached. Detection
                    rule generation is unaffected and remains fully usable.
                  </p>
                </div>
                {result.error && (
                  <Disclosure summary={<span className="text-xs">Technical details</span>}>
                    <pre className="overflow-auto rounded-md border border-line bg-canvas px-3 py-2 font-mono text-[0.68rem] leading-relaxed whitespace-pre-wrap text-ink-faint">
                      {result.error}
                    </pre>
                  </Disclosure>
                )}
              </>
            )}
          </div>
        )}
      </div>
    </Panel>
  )
}
