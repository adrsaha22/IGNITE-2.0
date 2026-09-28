import { useCallback, useEffect, useState } from 'react'
import {
  CheckCircle2,
  FlaskConical,
  Info,
  Loader2,
  Play,
  Plus,
  Trash2,
  TriangleAlert,
  XCircle,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { CodePanel } from '@/components/ui/code-panel'
import {
  Badge,
  Disclosure,
  EmptyState,
  Panel,
  PanelHeader,
  SectionLabel,
} from '@/components/ui/primitives'
import { useToast } from '@/components/ui/toast'
import { ApiError, getSampleSets, runRuleTest } from '@/lib/api'
import { cn } from '@/lib/utils'
import type { Analysis, RuleTestResult, SampleSet } from '@/types/api'

export interface TestCase {
  id: string
  /** JSON text as edited by the analyst. */
  json: string
  label: string
}

function newId() {
  return `tc-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`
}

/**
 * Detection Rule Testing Lab.
 *
 * Runs the selected rule against synthetic events using IGNITE's local SPL
 * subset evaluator. This is explicitly not Splunk: unsupported constructs are
 * listed rather than silently folded into a verdict.
 */
export function TestLabTab({
  analysis,
  selectedIndex,
  testCases,
  onTestCasesChange,
}: {
  analysis: Analysis
  selectedIndex: number
  testCases: TestCase[]
  onTestCasesChange: (cases: TestCase[]) => void
}) {
  const toast = useToast()
  const [samples, setSamples] = useState<SampleSet[]>([])
  const [result, setResult] = useState<RuleTestResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const selected = analysis.candidates[selectedIndex] ?? analysis.best
  const rule = selected?.spl ?? ''

  useEffect(() => {
    getSampleSets()
      .then(setSamples)
      .catch(() => setSamples([]))
  }, [])

  const loadSample = useCallback(
    (sample: SampleSet) => {
      const loaded: TestCase[] = sample.events.map((event) => ({
        id: newId(),
        label: String(event._id ?? 'event'),
        json: JSON.stringify(event, null, 2),
      }))
      onTestCasesChange(loaded)
      setResult(null)
      toast(`Loaded ${loaded.length} sample events`, 'success')
    },
    [onTestCasesChange, toast],
  )

  const run = useCallback(async () => {
    setError(null)
    const events: Record<string, unknown>[] = []

    for (const testCase of testCases) {
      try {
        const parsed = JSON.parse(testCase.json)
        if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
          setError(`"${testCase.label}" is not a JSON object.`)
          return
        }
        events.push({ _id: testCase.label, ...parsed })
      } catch {
        setError(`"${testCase.label}" is not valid JSON.`)
        return
      }
    }

    if (events.length === 0) {
      setError('Add at least one test event.')
      return
    }

    setLoading(true)
    try {
      setResult(await runRuleTest(rule, events))
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'The test could not be run.')
    } finally {
      setLoading(false)
    }
  }, [rule, testCases])

  return (
    <div className="space-y-5">
      {/* Scope statement — this must never be mistaken for Splunk validation. */}
      <Panel className="border-line">
        <div className="flex items-start gap-2.5 p-4 text-xs leading-relaxed text-ink-muted">
          <Info className="mt-0.5 size-4 shrink-0 text-primary-bright" />
          <div className="space-y-1.5">
            <p>
              Events are matched by IGNITE's <span className="text-ink">local SPL subset
              evaluator</span> — not by Splunk. It understands field comparisons, wildcards and
              numeric operators. Anything else is listed as unsupported and is not applied.
            </p>
            <p>
              This is a third, separate status alongside{' '}
              <span className="text-ink">static checks</span> and{' '}
              <span className="text-ink">external runtime validation</span>, which this tool does
              not perform.
            </p>
          </div>
        </div>
      </Panel>

      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
        {/* Rule under test */}
        <Panel>
          <PanelHeader
            title="Rule under test"
            description={selected ? selected.origin : 'No rule selected'}
            icon={<FlaskConical className="size-4" />}
            actions={
              selected ? (
                <Badge tone="primary" mono>
                  {selected.score} / {selected.score_max}
                </Badge>
              ) : undefined
            }
          />
          <div className="p-4">
            <CodePanel code={rule} maxHeight={220} />
          </div>
        </Panel>

        {/* Test events */}
        <Panel>
          <PanelHeader
            title={`Test events (${testCases.length})`}
            description="Synthetic JSON events. Include both matching and non-matching examples."
            actions={
              <Button
                variant="ghost"
                size="sm"
                onClick={() =>
                  onTestCasesChange([
                    ...testCases,
                    {
                      id: newId(),
                      label: `event-${testCases.length + 1}`,
                      json: '{\n  "EventCode": 1,\n  "Image": "",\n  "CommandLine": ""\n}',
                    },
                  ])
                }
              >
                <Plus />
                Add event
              </Button>
            }
          />
          <div className="space-y-3 p-4">
            {samples.length > 0 && (
              <div>
                <SectionLabel>Load a sample scenario</SectionLabel>
                <div className="flex flex-wrap gap-1.5">
                  {samples.map((sample) => (
                    <button
                      key={sample.key}
                      type="button"
                      onClick={() => loadSample(sample)}
                      title={sample.description}
                      className="rounded-full border border-line bg-raised px-2.5 py-1 text-xs text-ink-muted transition-colors hover:border-primary-line hover:text-primary-bright"
                    >
                      {sample.label}
                    </button>
                  ))}
                </div>
              </div>
            )}

            {testCases.length === 0 ? (
              <EmptyState message="No test events yet. Load a sample scenario or add one manually." />
            ) : (
              <div className="space-y-2">
                {testCases.map((testCase) => (
                  <div key={testCase.id} className="rounded-lg border border-line bg-canvas p-2.5">
                    <div className="mb-2 flex items-center gap-2">
                      <label className="sr-only" htmlFor={`label-${testCase.id}`}>
                        Event name
                      </label>
                      <input
                        id={`label-${testCase.id}`}
                        value={testCase.label}
                        onChange={(event) =>
                          onTestCasesChange(
                            testCases.map((item) =>
                              item.id === testCase.id
                                ? { ...item, label: event.target.value }
                                : item,
                            ),
                          )
                        }
                        className="min-w-0 flex-1 rounded border border-line bg-raised px-2 py-1 font-mono text-xs text-ink focus:border-primary-line focus:outline-none"
                      />
                      <Button
                        variant="ghost"
                        size="icon"
                        aria-label={`Remove ${testCase.label}`}
                        onClick={() =>
                          onTestCasesChange(testCases.filter((item) => item.id !== testCase.id))
                        }
                      >
                        <Trash2 />
                      </Button>
                    </div>
                    <label className="sr-only" htmlFor={`json-${testCase.id}`}>
                      Event JSON for {testCase.label}
                    </label>
                    <textarea
                      id={`json-${testCase.id}`}
                      value={testCase.json}
                      onChange={(event) =>
                        onTestCasesChange(
                          testCases.map((item) =>
                            item.id === testCase.id ? { ...item, json: event.target.value } : item,
                          ),
                        )
                      }
                      rows={5}
                      spellCheck={false}
                      className="w-full resize-y rounded border border-line bg-canvas px-2.5 py-2 font-mono text-[0.75rem] leading-relaxed text-ink focus:border-primary-line focus:outline-none"
                    />
                  </div>
                ))}
              </div>
            )}

            {error && (
              <div className="flex items-start gap-2 rounded-lg border border-bad/30 bg-bad-soft px-3 py-2">
                <TriangleAlert className="mt-0.5 size-3.5 shrink-0 text-bad" />
                <p className="text-xs text-bad">{error}</p>
              </div>
            )}

            <Button
              variant="primary"
              onClick={() => void run()}
              disabled={loading || testCases.length === 0 || !rule}
              className="w-full"
            >
              {loading ? <Loader2 className="animate-spin" /> : <Play />}
              {loading ? 'Running…' : 'Run local test'}
            </Button>
          </div>
        </Panel>
      </div>

      {/* Results */}
      {result && (
        <Panel>
          <PanelHeader
            title="Test results"
            description={result.disclaimer}
            actions={
              result.supported ? (
                <Badge tone={result.matched_count > 0 ? 'ok' : 'neutral'}>
                  {result.matched_count} of {result.total_count} matched
                </Badge>
              ) : (
                <Badge tone="warn">Not evaluable</Badge>
              )
            }
          />
          <div className="space-y-4 p-4">
            {!result.supported && (
              <div className="flex items-start gap-2.5 rounded-lg border border-warn/30 bg-warn-soft px-3 py-2.5">
                <TriangleAlert className="mt-0.5 size-4 shrink-0 text-warn" />
                <p className="text-xs leading-relaxed text-warn">{result.error}</p>
              </div>
            )}

            {result.unsupported.length > 0 && (
              <div>
                <SectionLabel>Not applied by the local evaluator</SectionLabel>
                <ul className="space-y-1">
                  {result.unsupported.map((note) => (
                    <li key={note} className="flex gap-2 text-xs leading-relaxed text-ink-muted">
                      <span className="mt-1.5 size-1 shrink-0 rounded-full bg-warn" />
                      <span>{note}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {result.results.length > 0 && (
              <div className="space-y-2">
                {result.results.map((eventResult) => {
                  const matched = eventResult.outcome === 'match'
                  return (
                    <div
                      key={eventResult.event_id}
                      className={cn(
                        'rounded-lg border p-3',
                        matched ? 'border-ok/30 bg-ok-soft' : 'border-line bg-raised',
                      )}
                    >
                      <div className="flex flex-wrap items-center gap-2">
                        {matched ? (
                          <CheckCircle2 className="size-4 shrink-0 text-ok" />
                        ) : (
                          <XCircle className="size-4 shrink-0 text-ink-faint" />
                        )}
                        <span className="font-mono text-xs text-ink">{eventResult.event_id}</span>
                        <span className="text-xs text-ink-muted">{eventResult.reason}</span>
                      </div>

                      <Disclosure
                        className="mt-2"
                        summary={<span className="text-xs">Condition detail</span>}
                      >
                        <div className="space-y-1">
                          {eventResult.observations.map((observation, index) => (
                            <div
                              key={`${observation.field}-${index}`}
                              className="flex flex-wrap items-baseline gap-1.5 font-mono text-[0.72rem]"
                            >
                              {observation.matched ? (
                                <CheckCircle2 className="size-3 shrink-0 text-ok" />
                              ) : (
                                <XCircle className="size-3 shrink-0 text-bad" />
                              )}
                              <span className="text-accent">{observation.field}</span>
                              <span className="text-ink-muted">{observation.operator}</span>
                              <span className="text-ok">{observation.expected}</span>
                              <span className="text-ink-faint">
                                {observation.missing
                                  ? '· field not present in event'
                                  : `· actual: ${observation.actual}`}
                              </span>
                            </div>
                          ))}
                        </div>
                      </Disclosure>
                    </div>
                  )
                })}
              </div>
            )}
          </div>
        </Panel>
      )}
    </div>
  )
}
