import { CircleCheck, CircleX, Info, ShieldAlert, TriangleAlert } from 'lucide-react'
import { Badge, EmptyState, Panel, PanelHeader, SectionLabel } from '@/components/ui/primitives'
import { ScoreMeter } from '@/components/ui/score'
import type { Analysis } from '@/types/api'

function Findings({
  items,
  empty,
  tone,
}: {
  items: string[]
  empty: string
  tone: 'ok' | 'warn' | 'bad'
}) {
  if (items.length === 0) return <EmptyState message={empty} />
  const dot = tone === 'ok' ? 'bg-ok' : tone === 'warn' ? 'bg-warn' : 'bg-bad'
  return (
    <ul className="space-y-1.5">
      {items.map((item) => (
        <li key={item} className="flex gap-2.5 text-xs leading-relaxed text-ink-muted">
          <span className={`mt-1.5 size-1 shrink-0 rounded-full ${dot}`} />
          <span>{item}</span>
        </li>
      ))}
    </ul>
  )
}

/**
 * Validation reporting.
 *
 * A passing boolean never suppresses warnings: when the validator reports
 * valid=true alongside unresolved issues, the contradiction is shown at the top
 * of the tab.
 */
export function ValidationTab({ analysis }: { analysis: Analysis }) {
  const auto = analysis.autonomous

  if (!auto.available) {
    return (
      <Panel>
        <PanelHeader
          title="Autonomous engine unavailable"
          icon={<CircleX className="size-4 text-bad" />}
        />
        <div className="p-4">
          <EmptyState
            message={`Validation and quality reports require the autonomous engine. Reported error: ${
              auto.error ?? 'unknown'
            }`}
          />
        </div>
      </Panel>
    )
  }

  const validation = auto.validation
  const quality = auto.quality
  const issues = validation.issues ?? []
  const contradictory = Boolean(validation.valid) && issues.length > 0

  return (
    <div className="space-y-5">
      {contradictory && (
        <Panel className="border-warn/40 bg-warn-soft">
          <div className="flex items-start gap-3 p-4">
            <ShieldAlert className="mt-0.5 size-5 shrink-0 text-warn" />
            <div>
              <h3 className="text-sm font-semibold text-warn">
                Contradictory validation report
              </h3>
              <p className="mt-1 text-xs leading-relaxed text-ink-muted">
                The validator marked this rule <span className="font-mono text-ink">valid</span>{' '}
                while also reporting {issues.length} unresolved issue
                {issues.length === 1 ? '' : 's'}. The pass status alone is not sufficient grounds
                to deploy this rule — read the issues below.
              </p>
            </div>
          </div>
        </Panel>
      )}

      <div className="grid gap-4 md:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_minmax(0,1.1fr)]">
        <Panel className="p-4">
          <ScoreMeter
            label="Validation score"
            value={validation.score}
            max={validation.score_max}
            caveat="Static text checks on the query"
          />
        </Panel>
        <Panel className="p-4">
          <ScoreMeter
            label="Quality score"
            value={quality.quality_score}
            max={quality.score_max}
            caveat="Heuristic field-presence score"
          />
        </Panel>
        <Panel className="flex flex-col justify-center p-4">
          <SectionLabel>Reported status</SectionLabel>
          <div className="flex items-center gap-2">
            {validation.valid ? (
              <CircleCheck className={`size-5 ${contradictory ? 'text-warn' : 'text-ok'}`} />
            ) : (
              <CircleX className="size-5 text-bad" />
            )}
            <span className="text-lg font-semibold text-ink">
              {validation.valid ? 'Valid' : 'Invalid'}
            </span>
            <Badge tone={issues.length > 0 ? 'warn' : 'neutral'}>
              {issues.length} issue{issues.length === 1 ? '' : 's'}
            </Badge>
          </div>
        </Panel>
      </div>

      <Panel className="border-line">
        <div className="flex items-start gap-2.5 p-4 text-xs leading-relaxed text-ink-muted">
          <Info className="mt-0.5 size-4 shrink-0 text-primary-bright" />
          <div className="space-y-2">
            <p>
              <span className="font-medium text-ink">Generated</span> — produced by the template
              and knowledge-base pipeline.{' '}
              <span className="font-medium text-ink">Statically checked</span> — inspected as text
              for required fields, event codes and attack indicators.{' '}
              <span className="font-medium text-ink">Externally validated</span> — not performed.
            </p>
            <p>
              This tool never contacts a Splunk instance, so no rule here is verified to parse or
              to fire correctly in production. Scores are heuristics, not calibrated
              probabilities.
            </p>
          </div>
        </div>
      </Panel>

      <div className="grid gap-4 md:grid-cols-2">
        <Panel>
          <PanelHeader
            title="Reported issues"
            icon={<TriangleAlert className="size-4 text-warn" />}
          />
          <div className="p-4">
            <Findings items={issues} empty="No issues reported by the validator." tone="warn" />
          </div>
        </Panel>

        <Panel>
          <PanelHeader title="Strengths" icon={<CircleCheck className="size-4 text-ok" />} />
          <div className="p-4">
            <Findings items={quality.strengths ?? []} empty="No strengths reported." tone="ok" />
          </div>
        </Panel>

        <Panel>
          <PanelHeader title="Weaknesses" icon={<CircleX className="size-4 text-bad" />} />
          <div className="p-4">
            <Findings items={quality.weaknesses ?? []} empty="No weaknesses reported." tone="bad" />
          </div>
        </Panel>

        <Panel>
          <PanelHeader title="False-positive considerations" icon={<Info className="size-4" />} />
          <div className="p-4">
            <p className="text-xs leading-relaxed text-ink-muted">
              Rules of this shape commonly fire on legitimate activity: administrative scripting,
              software deployment tooling, patch management and automation frameworks. Baseline
              the query against known-good activity in your own environment before enabling any
              alerting on it.
            </p>
          </div>
        </Panel>
      </div>
    </div>
  )
}
