import { CircleAlert, Crosshair, ShieldCheck, ShieldX, Target, TriangleAlert } from 'lucide-react'
import { CodePanel } from '@/components/ui/code-panel'
import { Badge, EmptyState, Panel, PanelHeader, SectionLabel } from '@/components/ui/primitives'
import { ScoreMeter, Stat } from '@/components/ui/score'
import type { Analysis } from '@/types/api'
import { isGenerated } from '@/lib/generation'
import { fileStamp } from '@/lib/utils'

/**
 * Overview gives the best rule the dominant position and keeps secondary
 * numbers visually subordinate, rather than laying out a row of identical
 * metric cards.
 */
export function OverviewTab({ analysis }: { analysis: Analysis }) {
  const { autonomous: auto, best } = analysis
  const validation = auto.validation
  const quality = auto.quality
  const issues = validation.issues ?? []
  // Generated analyses carry the backend's weighted quality checks.
  const checked = isGenerated(analysis) && validation.valid !== null

  const status = (() => {
    if (!auto.available) {
      return { tone: 'warn' as const, label: 'Engine unavailable', icon: CircleAlert }
    }
    if (validation.valid && issues.length > 0) {
      return { tone: 'warn' as const, label: 'Passed with warnings', icon: TriangleAlert }
    }
    if (validation.valid) {
      return {
        tone: 'ok' as const,
        label: checked ? 'Passed quality checks' : 'Passed static checks',
        icon: ShieldCheck,
      }
    }
    if (validation.valid === null) {
      return { tone: 'warn' as const, label: 'Not scored', icon: CircleAlert }
    }
    return {
      tone: 'bad' as const,
      label: checked ? 'Failed quality checks' : 'Failed static checks',
      icon: ShieldX,
    }
  })()

  const StatusIcon = status.icon

  return (
    <div className="grid items-start gap-5 lg:grid-cols-[minmax(0,1.85fr)_minmax(0,1fr)]">
      {/* Primary column: the rule itself. */}
      <div className="space-y-4">
        <Panel>
          <PanelHeader
            title="Best detection rule"
            description={
              best
                ? `${best.origin} · ${analysis.rule_status}`
                : 'No candidate rules were produced.'
            }
            icon={<Target className="size-4" />}
            actions={
              best ? (
                <Badge tone="primary" mono>
                  {best.score} / {best.score_max}
                </Badge>
              ) : undefined
            }
          />
          <div className="p-4">
            {best ? (
              <>
                {!best.has_conditions && (
                  <div className="mb-3 flex items-start gap-2 rounded-md border border-warn/30 bg-warn-soft px-3 py-2 text-xs text-warn">
                    <TriangleAlert className="mt-0.5 size-3.5 shrink-0" />
                    <span>
                      This rule has no field conditions and would match far more events than
                      intended.
                    </span>
                  </div>
                )}
                <CodePanel
                  code={best.spl}
                  filename={`ignite_best_rule_${fileStamp(analysis.generated_at)}.spl`}
                  maxHeight={300}
                />
              </>
            ) : (
              <EmptyState message="No candidate rules were produced for this description." />
            )}
          </div>
        </Panel>

        {analysis.warnings.length > 0 && (
          <Panel className="border-warn/25">
            <PanelHeader
              title={`Review before use — ${analysis.warnings.length} finding${
                analysis.warnings.length === 1 ? '' : 's'
              }`}
              icon={<TriangleAlert className="size-4 text-warn" />}
            />
            <ul className="divide-y divide-line">
              {analysis.warnings.map((warning) => (
                <li key={warning} className="flex gap-2.5 px-4 py-2.5 text-xs leading-relaxed">
                  <span className="mt-1.5 size-1 shrink-0 rounded-full bg-warn" />
                  <span className="text-ink-muted">{warning}</span>
                </li>
              ))}
            </ul>
          </Panel>
        )}

        {/* Analysed input, kept in the primary column so both columns fill. */}
        <Panel className="p-4">
          <SectionLabel>Analysed scenario</SectionLabel>
          <p className="text-xs leading-relaxed text-ink-muted">{analysis.description}</p>
        </Panel>
      </div>

      {/* Secondary column: scores and context. */}
      <div className="space-y-4">
        <Panel className="p-4">
          <div
            className={`mb-4 flex items-center gap-2 rounded-md border px-3 py-2 text-xs font-medium ${
              status.tone === 'ok'
                ? 'border-ok/30 bg-ok-soft text-ok'
                : status.tone === 'warn'
                  ? 'border-warn/30 bg-warn-soft text-warn'
                  : 'border-bad/30 bg-bad-soft text-bad'
            }`}
          >
            <StatusIcon className="size-4 shrink-0" />
            <span>{status.label}</span>
          </div>

          <div className="space-y-4">
            <ScoreMeter
              label={checked ? 'Checks passed' : 'Validation'}
              value={validation.score}
              max={validation.score_max}
              caveat={
                checked
                  ? 'Of the weighted checks that ran'
                  : 'Static text checks, not runtime validation'
              }
            />
            <ScoreMeter
              label="Rule quality"
              value={quality.quality_score}
              max={quality.score_max}
              caveat={
                checked
                  ? 'Weighted quality score; any failure caps it at 49'
                  : 'Heuristic, not a measure of effectiveness'
              }
            />
            {best && (
              <ScoreMeter
                label="Best rule score"
                value={best.score}
                max={best.score_max}
                caveat="Ranking score on its own scale"
              />
            )}
          </div>

          <div className="mt-4 grid grid-cols-2 gap-3 border-t border-line pt-4">
            <Stat
              label="Techniques"
              value={auto.techniques.length}
              note="ATT&CK mapped"
              tone="primary"
            />
            <Stat label="Candidates" value={analysis.candidates.length} note="rules ranked" />
          </div>
        </Panel>

        <Panel className="p-4">
          <SectionLabel>Primary technique</SectionLabel>
          {analysis.primary_technique.id === 'Unknown' ? (
            <EmptyState
              icon={<Crosshair className="size-3.5" />}
              message="No technique matched the description."
            />
          ) : (
            <div className="flex flex-wrap items-center gap-2">
              <Badge tone="primary" mono>
                {analysis.primary_technique.id}
              </Badge>
              <span className="text-sm text-ink">{analysis.primary_technique.name}</span>
            </div>
          )}

        </Panel>
      </div>
    </div>
  )
}
