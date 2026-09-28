import { useCallback, useEffect, useRef, useState } from 'react'
import { AnimatePresence, motion } from 'motion/react'
import {
  Bot,
  KeyRound,
  Loader2,
  RefreshCw,
  Send,
  Sparkles,
  TriangleAlert,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import {
  Badge,
  Disclosure,
  EmptyState,
  Panel,
  PanelHeader,
  SectionLabel,
} from '@/components/ui/primitives'
import { ApiError, askCopilot, getCopilotStatus } from '@/lib/api'
import { useReducedMotion } from '@/lib/motion'
import { cn } from '@/lib/utils'
import type {
  Analysis,
  CopilotAction,
  CopilotResult,
  CopilotStatus,
  CopilotTurn,
} from '@/types/api'

/** Contextual actions offered for the current selection. */
const ACTIONS: { action: CopilotAction; label: string }[] = [
  { action: 'explain_rule', label: 'Explain this rule' },
  { action: 'explain_conditions', label: 'Explain the conditions' },
  { action: 'find_gaps', label: 'Find blind spots' },
  { action: 'reduce_false_positives', label: 'Reduce false positives' },
  { action: 'explain_validation', label: 'Explain validation findings' },
  { action: 'explain_attack', label: 'Explain ATT&CK mapping' },
  { action: 'suggest_telemetry', label: 'Suggest telemetry' },
]

/** Human wording for each failure mode. */
const STATUS_HINT: Record<string, string> = {
  not_configured: 'Set GEMINI_API_KEY in the backend environment to enable the Copilot.',
  unauthorized: 'The configured API key was rejected. Check GEMINI_API_KEY.',
  rate_limited: 'Free-tier quota reached. Wait a moment before retrying.',
  timeout: 'The provider did not respond in time.',
  unreachable: 'The provider could not be reached.',
  provider_error: 'The provider returned an error.',
  malformed: 'The provider returned an unreadable response.',
  blocked: 'The provider declined to answer this request.',
}

/**
 * AI Detection Copilot.
 *
 * Sends only the current scenario, selected rule, validation findings and
 * ATT&CK mappings — never the whole application state. Answers are rendered as
 * plain text and clearly labelled as AI-generated.
 */
export function CopilotPanel({
  analysis,
  selectedIndex,
}: {
  analysis: Analysis | null
  selectedIndex: number
}) {
  const reduced = useReducedMotion()
  const [status, setStatus] = useState<CopilotStatus | null>(null)
  const [result, setResult] = useState<CopilotResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [question, setQuestion] = useState('')
  const [history, setHistory] = useState<CopilotTurn[]>([])
  const [lastAction, setLastAction] = useState<CopilotAction | null>(null)

  // Avoids re-issuing an identical request that is already in flight.
  const inFlight = useRef(false)

  const checkStatus = useCallback(async () => {
    try {
      setStatus(await getCopilotStatus())
    } catch {
      setStatus(null)
    }
  }, [])

  useEffect(() => {
    void checkStatus()
  }, [checkStatus])

  const selected = analysis?.candidates[selectedIndex] ?? analysis?.best ?? null

  const run = useCallback(
    async (action: CopilotAction, asked = '') => {
      if (inFlight.current || !analysis) return
      inFlight.current = true
      setLoading(true)
      setLastAction(action)

      try {
        const response = await askCopilot({
          action,
          question: asked,
          // Bounded context: only these fields leave the browser.
          context: {
            scenario: analysis.description,
            rule: selected?.spl ?? '',
            rule_origin: selected?.origin ?? '',
            techniques: analysis.autonomous.techniques.map((t) => ({
              id: t.id,
              name: t.name,
            })),
            validation_issues: analysis.autonomous.validation.issues ?? [],
            quality: {
              strengths: analysis.autonomous.quality.strengths ?? [],
              weaknesses: analysis.autonomous.quality.weaknesses ?? [],
            },
            entities: { tools: analysis.entities.tools },
          },
          history,
        })

        setResult(response)

        if (response.ok) {
          // Keep a small bounded history so follow-ups stay coherent.
          setHistory((current) =>
            [
              ...current,
              { role: 'user' as const, content: asked || action },
              { role: 'assistant' as const, content: response.text.slice(0, 1500) },
            ].slice(-6),
          )
        }
      } catch (error) {
        setResult({
          ok: false,
          status: 'provider_error',
          text: '',
          sections: [],
          message:
            error instanceof ApiError
              ? error.message
              : 'The Copilot request could not be completed.',
          model: '',
          ai_generated: true,
        })
      } finally {
        setLoading(false)
        inFlight.current = false
      }
    },
    [analysis, selected, history],
  )

  const configured = status?.configured ?? false
  const disabled = !analysis || loading

  return (
    <Panel>
      <PanelHeader
        title="AI Detection Copilot"
        description="Explains and critiques the selected rule. Rule generation never depends on it."
        icon={<Sparkles className="size-4" />}
        actions={
          <div className="flex flex-wrap items-center gap-2">
            {status && (
              <Badge tone={configured ? 'ok' : 'warn'}>
                {configured ? `Ready · ${status.model}` : 'Not configured'}
              </Badge>
            )}
            <Button
              variant="ghost"
              size="sm"
              onClick={() => void checkStatus()}
              aria-label="Re-check Copilot configuration"
            >
              <RefreshCw />
              Recheck
            </Button>
          </div>
        }
      />

      <div className="space-y-4 p-4">
        {!configured && status && (
          <div className="flex items-start gap-2.5 rounded-xl border border-warn/30 bg-warn-soft px-3.5 py-3">
            <KeyRound className="mt-0.5 size-4 shrink-0 text-warn" />
            <div className="min-w-0">
              <p className="text-xs leading-relaxed text-warn">
                {status.message || STATUS_HINT.not_configured}
              </p>
              <p className="mt-1 text-[0.7rem] text-ink-faint">
                Detection rule generation, testing and validation all work without it.
              </p>
            </div>
          </div>
        )}

        {!analysis ? (
          <EmptyState message="Generate detection rules first — the Copilot works from the current investigation." />
        ) : (
          <>
            <div>
              <SectionLabel>Ask about the selected rule</SectionLabel>
              <div className="flex flex-wrap gap-1.5">
                {ACTIONS.map(({ action, label }) => (
                  <button
                    key={action}
                    type="button"
                    onClick={() => void run(action)}
                    disabled={disabled || !configured}
                    className={cn(
                      'rounded-full border px-2.5 py-1 text-xs',
                      'transition-[color,border-color,transform] duration-[var(--dur-fast)]',
                      'disabled:cursor-not-allowed disabled:opacity-45',
                      lastAction === action && loading
                        ? 'border-primary-line bg-primary-soft text-primary-bright'
                        : 'border-line bg-raised text-ink-muted hover:border-primary-line hover:text-primary-bright active:scale-[0.97]',
                    )}
                  >
                    {label}
                  </button>
                ))}
              </div>
            </div>

            <form
              onSubmit={(event) => {
                event.preventDefault()
                const asked = question.trim()
                if (asked) {
                  void run('ask', asked)
                  setQuestion('')
                }
              }}
              className="flex gap-2"
            >
              <label htmlFor="copilot-question" className="sr-only">
                Ask a follow-up question
              </label>
              <input
                id="copilot-question"
                value={question}
                onChange={(event) => setQuestion(event.target.value)}
                placeholder="Ask a follow-up about this investigation…"
                disabled={disabled || !configured}
                maxLength={2000}
                className="min-w-0 flex-1 rounded-lg border border-line bg-canvas px-3 py-2 text-sm text-ink placeholder:text-ink-faint focus:border-primary-line focus:outline-none disabled:opacity-45"
              />
              <Button
                type="submit"
                variant="outline"
                disabled={disabled || !configured || !question.trim()}
                aria-label="Send question"
              >
                <Send />
              </Button>
            </form>

            {loading && (
              <div className="flex items-center gap-2 text-xs text-ink-muted">
                <Loader2 className="size-3.5 animate-spin text-primary-bright" />
                Asking the Copilot…
              </div>
            )}

            <AnimatePresence mode="wait">
              {result && !loading && (
                <motion.div
                  key={result.status + result.text.slice(0, 20)}
                  initial={reduced ? false : { opacity: 0, y: 6 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={reduced ? { duration: 0 } : { duration: 0.24 }}
                >
                  {result.ok ? (
                    <div className="space-y-3">
                      <div className="flex flex-wrap items-center gap-2">
                        <Badge tone="primary">
                          <Bot className="size-3" />
                          AI-generated
                        </Badge>
                        {result.model && (
                          <span className="font-mono text-[0.68rem] text-ink-faint">
                            {result.model}
                          </span>
                        )}
                      </div>

                      {result.sections.length > 0 ? (
                        <div className="space-y-3">
                          {result.sections.map((section) => (
                            <div key={section.heading}>
                              <SectionLabel>{section.heading}</SectionLabel>
                              {/* Plain text only — model output is never rendered as HTML. */}
                              <p className="text-xs leading-relaxed whitespace-pre-wrap text-ink-muted">
                                {section.body}
                              </p>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <p className="rounded-lg border border-line bg-canvas px-3.5 py-3 text-xs leading-relaxed whitespace-pre-wrap text-ink">
                          {result.text}
                        </p>
                      )}

                      <p className="text-[0.68rem] leading-relaxed text-ink-faint">
                        AI output can be wrong. Verify suggestions against your own telemetry
                        before changing a detection.
                      </p>
                    </div>
                  ) : (
                    <div className="space-y-2">
                      <div className="flex items-start gap-2.5 rounded-xl border border-warn/30 bg-warn-soft px-3.5 py-3">
                        <TriangleAlert className="mt-0.5 size-4 shrink-0 text-warn" />
                        <div className="min-w-0 flex-1">
                          <p className="text-xs leading-relaxed text-warn">
                            {result.message || STATUS_HINT[result.status] || 'Request failed.'}
                          </p>
                          {lastAction && (
                            <button
                              onClick={() => void run(lastAction)}
                              className="mt-1.5 text-xs font-medium text-primary-bright underline-offset-2 hover:underline"
                            >
                              Retry
                            </button>
                          )}
                        </div>
                      </div>
                      <Disclosure summary={<span className="text-xs">Technical details</span>}>
                        <pre className="overflow-auto rounded-md border border-line bg-canvas px-3 py-2 font-mono text-[0.68rem] text-ink-faint">
                          status: {result.status}
                        </pre>
                      </Disclosure>
                    </div>
                  )}
                </motion.div>
              )}
            </AnimatePresence>
          </>
        )}
      </div>
    </Panel>
  )
}
