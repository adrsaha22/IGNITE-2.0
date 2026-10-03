import { CircleCheck, CircleX, Gauge, Info, ShieldAlert, TriangleAlert } from 'lucide-react'
import { Badge, EmptyState, Panel, PanelHeader, SectionLabel } from '@/components/ui/primitives'
import { ChecksList, GradeBadge, checkCounts } from '@/components/ui/quality'
import { ScoreMeter } from '@/components/ui/score'
import { isGenerated } from '@/lib/generation'
import type { Analysis, GeneratedCandidate } from '@/types/api'

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

const STAGE_TONE: Record<string, string> = {
  run: 'text-ok',
  passed: 'text-ok',
  failed: 'text-bad',
}

/** Validation for an LLM-generated candidate: the backend's weighted checks. */
function GeneratedValidation({ candidate }: { candidate: GeneratedCandidate }) {
  const quality = candidate.validation
  const stages = candidate.provenance?.validation

  if (!quality) {
    return (
      <EmptyState message="This result predates IGNITE's quality checks. Generate again, or save it to the rule library, to run them." />
    )
  }

  const counts = checkCounts(quality.checks)
  const parserRan = quality.splunk_parser !== 'not_configured'

  return (
    <div className="space-y-5">
      <div className="grid gap-4 md:grid-cols-3">
        <Panel className="p-4">
          <ScoreMeter
            label="Quality score"
            value={quality.quality_score}
            max={100}
            caveat="Weighted; any failure caps it at 49"
          />
        </Panel>
        <Panel className="p-4">
          <ScoreMeter
            label="Checks passed"
            value={counts.pass}
            max={counts.pass + counts.warn + counts.fail}
            caveat={`${counts.skip} skipped (not counted)`}
          />
        </Panel>
        <Panel className="flex flex-col justify-center gap-2 p-4">
          <SectionLabel>Grade</SectionLabel>
          <div className="flex items-center gap-2">
            {quality.passed ? (
              <CircleCheck className="size-5 text-ok" />
            ) : (
              <CircleX className="size-5 text-bad" />
            )}
            <GradeBadge score={quality.quality_score} grade={quality.quality_grade} />
          </div>
        </Panel>
      </div>

      <div className="grid items-start gap-4 lg:grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)]">
        <Panel>
          <PanelHeader
            title={`Quality checks — ${candidate.name}`}
            icon={<Gauge className="size-4" />}
          />
          <div className="px-4 py-2">
            <ChecksList checks={quality.checks} />
          </div>
        </Panel>

        <Panel>
          <PanelHeader title="What was validated" icon={<Info className="size-4" />} />
          <div className="space-y-3 p-4 text-xs leading-relaxed text-ink-muted">
            {stages && (
              <ul className="space-y-1 font-mono text-[0.7rem]">
                {Object.entries(stages).map(([stage, value]) => (
                  <li key={stage} className={STAGE_TONE[value] ?? 'text-warn'}>
                    {stage.replace(/_/g, ' ')}: {value}
                  </li>
                ))}
              </ul>
            )}
            <p>
              Quality checks inspect the SPL, the Sigma rule, the ATT&amp;CK mapping, false
              positives and response steps.{' '}
              {parserRan
                ? "Splunk's own parser was also asked whether the SPL is valid."
                : 'Splunk is not connected, so the SPL has not been checked by a real parser.'}
            </p>
            <p>
              None of this runs the rule against real telemetry. Save it to the rule library, run a
              test search, and deploy in shadow mode to measure real alert volume before going
              live.
            </p>
          </div>
        </Panel>
      </div>
    </div>
  )
}

/**
 * Validation reporting.
 *
 * A passing boolean never suppresses warnings: when the validator reports
 * valid=true alongside unresolved issues, the contradiction is shown at the top
 * of the tab.
 */
export function ValidationTab({
  analysis,
  selectedIndex = 0,
}: {
  analysis: Analysis
  selectedIndex?: number
}) {
  const auto = analysis.autonomous

  if (isGenerated(analysis)) {
    const candidate =
      analysis.generation.candidates[selectedIndex] ?? analysis.generation.candidates[0]
    // Records from before quality checks existed fall through to the
    // "not scored" view below rather than showing invented numbers.
    if (candidate?.validation) return <GeneratedValidation candidate={candidate} />
  }

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
              Static checking never contacts a Splunk instance, so no rule here is verified to
              parse or to fire correctly in production. Scores are heuristics, not calibrated
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
