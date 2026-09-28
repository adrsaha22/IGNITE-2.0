import { Bot, Check, FileCode, Radar, TriangleAlert } from 'lucide-react'
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
import type { Analysis } from '@/types/api'
import { isGenerated } from '@/lib/generation'
import { GeneratedDetail } from './GeneratedDetail'
import { cn, fileStamp, scorePercent } from '@/lib/utils'

/**
 * Rule inspection. A candidate list on the left drives a single detail panel,
 * so alternatives can be compared without scrolling past several full-length
 * code blocks.
 */
export function RulesTab({
  analysis,
  selectedIndex,
  onSelect,
}: {
  analysis: Analysis
  selectedIndex: number
  onSelect: (index: number) => void
}) {
  const toast = useToast()
  const { candidates, autonomous: auto } = analysis
  const selected = candidates[selectedIndex] ?? candidates[0] ?? null
  const stamp = fileStamp(analysis.generated_at)

  if (candidates.length === 0) {
    return <EmptyState message="No candidate rules were produced for this description." />
  }

  return (
    <div className="space-y-5">
      <div className="grid items-start gap-4 lg:grid-cols-[minmax(0,17rem)_minmax(0,1fr)]">
        {/* Candidate selector */}
        <Panel className="overflow-hidden">
          <PanelHeader title={`Candidates (${candidates.length})`} icon={<Radar className="size-4" />} />
          <ul role="radiogroup" aria-label="Candidate detection rules" className="divide-y divide-line">
            {candidates.map((candidate, index) => {
              const active = index === selectedIndex
              return (
                <li key={`${candidate.origin}-${index}`}>
                  <button
                    role="radio"
                    aria-checked={active}
                    onClick={() => onSelect(index)}
                    className={cn(
                      'flex w-full items-start gap-2.5 px-3.5 py-3 text-left transition-colors',
                      active ? 'bg-primary-soft' : 'hover:bg-raised',
                    )}
                  >
                    <span
                      className={cn(
                        'mt-0.5 flex size-4 shrink-0 items-center justify-center rounded-full border',
                        active ? 'border-primary bg-primary' : 'border-line-strong',
                      )}
                    >
                      {active && <Check className="size-2.5 text-primary-contrast" />}
                    </span>
                    <span className="min-w-0 flex-1">
                      <span
                        className={cn(
                          'block truncate text-xs font-medium',
                          active ? 'text-primary' : 'text-ink',
                        )}
                      >
                        #{index + 1} · {candidate.origin}
                      </span>
                      <span className="mt-1 flex items-center gap-2">
                        <span className="h-1 w-16 overflow-hidden rounded-full bg-line">
                          <span
                            className="block h-full rounded-full bg-primary/70"
                            style={{
                              width: `${scorePercent(candidate.score, candidate.score_max)}%`,
                            }}
                          />
                        </span>
                        <span className="font-mono text-[0.68rem] text-ink-faint">
                          {candidate.score}/{candidate.score_max}
                        </span>
                      </span>
                    </span>
                  </button>
                </li>
              )
            })}
          </ul>
        </Panel>

        {/* Selected rule detail */}
        {selected && (
          <Panel>
            <PanelHeader
              title={`Rule #${selectedIndex + 1} — ${selected.origin}`}
              description={analysis.rule_status}
              icon={<FileCode className="size-4" />}
              actions={
                <Badge tone={selected.has_conditions ? 'primary' : 'warn'} mono>
                  {selected.score} / {selected.score_max}
                </Badge>
              }
            />
            <div className="space-y-4 p-4">
              {!selected.has_conditions && (
                <div className="flex items-start gap-2 rounded-md border border-warn/30 bg-warn-soft px-3 py-2 text-xs text-warn">
                  <TriangleAlert className="mt-0.5 size-3.5 shrink-0" />
                  <span>
                    No field conditions detected in this query, so it would match far more events
                    than intended.
                  </span>
                </div>
              )}

              <CodePanel
                code={selected.spl}
                filename={`ignite_rule_${selectedIndex + 1}_${stamp}.spl`}
                maxHeight={340}
                onCopied={(ok) =>
                  toast(ok ? 'Rule copied to clipboard' : 'Could not copy to clipboard', ok ? 'success' : 'error')
                }
              />

              <div>
                <SectionLabel>How this score was produced</SectionLabel>
                <p className="text-xs leading-relaxed text-ink-muted">
                  The ranking score adds points for the presence of specific fields and indicators
                  in the query text — process-creation events, image and command-line filters,
                  parent-process context and aggregation. It is a text heuristic on its own{' '}
                  <span className="font-mono">0–{selected.score_max}</span> scale, not a
                  probability and not a measure of real-world detection effectiveness.
                </p>
              </div>

              {analysis.entities.logs.length > 0 && (
                <div>
                  <SectionLabel>Log sources referenced</SectionLabel>
                  <div className="flex flex-wrap gap-1.5">
                    {analysis.entities.logs.map((log) => (
                      <Badge key={log} tone="neutral">
                        {log}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </Panel>
        )}
      </div>

      {/* Candidate-specific LLM detail, keyed to the selected candidate so
          assumptions and mappings can never belong to another rule. */}
      {isGenerated(analysis) && analysis.generation.candidates[selectedIndex] && (
        <GeneratedDetail candidate={analysis.generation.candidates[selectedIndex]} />
      )}

      {/* Autonomous engine output */}
      <Panel>
        <PanelHeader
          title="Autonomous engine"
          description="Built from mapped techniques, then narrowed by the false-positive reducer."
          icon={<Bot className="size-4" />}
        />
        <div className="space-y-4 p-4">
          {auto.available ? (
            <>
              <CodePanel
                code={auto.rule}
                label="Autonomous rule"
                filename={`ignite_autonomous_${stamp}.spl`}
                maxHeight={240}
              />
              {auto.telemetry_rule.trim() && (
                <CodePanel
                  code={auto.telemetry_rule}
                  label="Telemetry-aware variant"
                  filename={`ignite_telemetry_${stamp}.spl`}
                  maxHeight={240}
                />
              )}
            </>
          ) : (
            <EmptyState message={`Autonomous engine unavailable: ${auto.error ?? 'unknown error'}`} />
          )}
        </div>
      </Panel>

      {/* Sigma references */}
      <Panel>
        <PanelHeader
          title={`Sigma references (${analysis.sigma_references.length})`}
          icon={<FileCode className="size-4" />}
        />
        <div className="p-4">
          {analysis.sigma_references.length === 0 ? (
            <EmptyState message="No Sigma rules matched. The data/sigma directory has no rule corpus, so this pipeline has nothing to search." />
          ) : (
            <div className="space-y-3">
              {analysis.sigma_references.map((reference, index) => (
                <Disclosure
                  key={`${reference.title}-${index}`}
                  summary={`${index + 1}. ${reference.title}`}
                >
                  <div className="space-y-2">
                    {reference.tags.length > 0 && (
                      <div className="flex flex-wrap gap-1.5">
                        {reference.tags.map((tag) => (
                          <Badge key={tag} tone="neutral" mono>
                            {tag}
                          </Badge>
                        ))}
                      </div>
                    )}
                    <CodePanel code={reference.spl} maxHeight={200} />
                  </div>
                </Disclosure>
              ))}
            </div>
          )}
        </div>
      </Panel>
    </div>
  )
}
