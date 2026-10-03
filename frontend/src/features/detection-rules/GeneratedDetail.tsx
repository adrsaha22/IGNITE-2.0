import { useState } from 'react'
import {
  BadgeCheck,
  BookMarked,
  Bot,
  CircleHelp,
  Database,
  EyeOff,
  FileCode,
  FlaskConical,
  Gauge,
  Info,
  Library,
  ListChecks,
  Loader2,
  Target,
  TriangleAlert,
  Wrench,
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
import { ChecksList, GradeBadge, checkCounts } from '@/components/ui/quality'
import { useToast } from '@/components/ui/toast'
import { ApiError, saveRule } from '@/lib/api'
import type { GeneratedCandidate } from '@/types/api'

function List({ items, empty }: { items: string[]; empty: string }) {
  if (items.length === 0) return <EmptyState message={empty} />
  return (
    <ul className="space-y-1.5">
      {items.map((item) => (
        <li key={item} className="flex gap-2.5 text-xs leading-relaxed text-ink-muted">
          <span className="mt-1.5 size-1 shrink-0 rounded-full bg-ink-faint" />
          <span>{item}</span>
        </li>
      ))}
    </ul>
  )
}

/**
 * Candidate-specific detail from the LLM generation path.
 *
 * Every field here belongs to one candidate, so switching candidates swaps the
 * whole panel — assumptions and mappings can never be attributed to the wrong
 * rule.
 */
/** Quality report plus the action that moves a candidate into governance. */
function QualityPanel({
  candidate,
  scenario,
  onSaved,
}: {
  candidate: GeneratedCandidate
  scenario: string
  onSaved?: (ruleId: string) => void
}) {
  const toast = useToast()
  const [saving, setSaving] = useState(false)
  const [savedId, setSavedId] = useState<string | null>(null)
  const quality = candidate.validation
  const repairs = candidate.provenance?.repair_attempts ?? 0

  async function handleSave() {
    setSaving(true)
    try {
      const rule = await saveRule(candidate, scenario)
      setSavedId(rule.id)
      toast('Saved to the rule library as a draft', 'success')
    } catch (err) {
      toast(err instanceof ApiError ? err.message : 'Could not save the rule', 'error')
    } finally {
      setSaving(false)
    }
  }

  const saveAction = savedId ? (
    <Button variant="outline" size="sm" onClick={() => onSaved?.(savedId)}>
      <Library />
      Open in library
    </Button>
  ) : (
    <Button variant="primary" size="sm" onClick={() => void handleSave()} disabled={saving}>
      {saving ? <Loader2 className="animate-spin" /> : <BookMarked />}
      Save to rule library
    </Button>
  )

  if (!quality) {
    return (
      <Panel>
        <PanelHeader
          title="Quality checks"
          description="This result predates quality checks. Saving it to the library runs them."
          icon={<ListChecks className="size-4" />}
          actions={saveAction}
        />
      </Panel>
    )
  }

  const counts = checkCounts(quality.checks)

  return (
    <Panel className={quality.passed ? undefined : 'border-bad/30'}>
      <PanelHeader
        title="Quality checks"
        description={`${counts.pass} passed · ${counts.warn} warnings · ${counts.fail} failed · ${counts.skip} skipped. Computed by IGNITE, not claimed by the model.`}
        icon={<Gauge className="size-4" />}
        actions={
          <>
            <GradeBadge score={quality.quality_score} grade={quality.quality_grade} />
            {saveAction}
          </>
        }
      />
      <div className="space-y-3 p-4">
        {repairs > 0 && (
          <div className="flex items-start gap-2 rounded-md border border-primary-line bg-primary-soft px-3 py-2 text-xs text-primary-bright">
            <Wrench className="mt-0.5 size-3.5 shrink-0" />
            <span>
              The first answer failed quality checks. The failures were sent back to the model;
              this is repair attempt {repairs}.
            </span>
          </div>
        )}
        {candidate.provenance?.repair_note && (
          <p className="text-xs text-warn">{candidate.provenance.repair_note}</p>
        )}
        {!quality.passed && (
          <div className="flex items-start gap-2 rounded-md border border-bad/30 bg-bad-soft px-3 py-2 text-xs text-bad">
            <TriangleAlert className="mt-0.5 size-3.5 shrink-0" />
            <span>
              This rule still fails {quality.failures.length} check
              {quality.failures.length === 1 ? '' : 's'}. Approving it in the library requires a
              written override justification.
            </span>
          </div>
        )}
        <ChecksList checks={quality.checks} />
        <p className="text-[0.7rem] leading-relaxed text-ink-faint">
          Score = weighted average (pass earns full weight, warning half, failure none; skipped
          checks are excluded). Any failure caps the score at 49. The checks inspect the rule text
          and structure
          {quality.splunk_parser === 'not_configured' ? '' : ', plus the Splunk parser'}. They do
          not prove the rule detects the attack.
        </p>
      </div>
    </Panel>
  )
}

export function GeneratedDetail({
  candidate,
  scenario = '',
  onSaved,
}: {
  candidate: GeneratedCandidate
  scenario?: string
  onSaved?: (ruleId: string) => void
}) {
  const validation = candidate.provenance?.validation
  const references = candidate.provenance?.grounding?.references ?? []
  // Demo candidates are pre-written templates, not model output. The label
  // must make that unmistakable wherever provenance is shown.
  const isDemo = candidate.provenance?.generator === 'template'

  return (
    <div className="space-y-4">
      <QualityPanel candidate={candidate} scenario={scenario} onSaved={onSaved} />

      {/* Provenance: what produced this, and which checks actually ran. */}
      <Panel>
        <PanelHeader
          title="Generation provenance"
          icon={<Bot className="size-4" />}
          actions={
            isDemo ? (
              <Badge tone="warn">
                <FlaskConical className="size-3" />
                DEMO · template-based
              </Badge>
            ) : (
              <Badge tone="primary">
                <Bot className="size-3" />
                LLM-generated
              </Badge>
            )
          }
        />
        {isDemo && (
          <div className="border-b border-line bg-warn-soft px-4 py-2.5">
            <p className="text-xs leading-relaxed text-warn">
              This is a pre-written demo template, not a rule generated for your scenario. It
              was not produced by a language model, has not been validated against Splunk, and
              is not evidence that this attack would be detected.
            </p>
          </div>
        )}
        <div className="grid gap-3 p-4 sm:grid-cols-2">
          <div>
            <SectionLabel>Produced by</SectionLabel>
            {isDemo ? (
              <>
                <p className="font-mono text-xs text-ink-muted">
                  offline template · no provider
                </p>
                <p className="mt-1 font-mono text-[0.68rem] text-ink-faint">
                  template {candidate.provenance?.template_version} · ATT&amp;CK dataset{' '}
                  {candidate.provenance?.attack_dataset_version}
                </p>
              </>
            ) : (
              <>
                <p className="font-mono text-xs text-ink-muted">
                  {candidate.provenance?.provider} · {candidate.provenance?.model}
                </p>
                <p className="mt-1 font-mono text-[0.68rem] text-ink-faint">
                  prompt {candidate.provenance?.prompt_version} · ATT&amp;CK dataset{' '}
                  {candidate.provenance?.attack_dataset_version}
                </p>
              </>
            )}
          </div>
          <div>
            <SectionLabel>Validation stages</SectionLabel>
            {validation ? (
              <ul className="space-y-1 font-mono text-[0.7rem]">
                <li className="text-ok">static checks: {validation.static_checks}</li>
                {validation.quality_checks && (
                  <li
                    className={validation.quality_checks === 'run' ? 'text-ok' : 'text-ink-muted'}
                  >
                    quality checks: {validation.quality_checks}
                  </li>
                )}
                <li className="text-ink-muted">
                  local sample test: {validation.local_sample_test}
                </li>
                <li
                  className={
                    validation.splunk_syntax_validation === 'passed'
                      ? 'text-ok'
                      : validation.splunk_syntax_validation === 'failed'
                        ? 'text-bad'
                        : 'text-warn'
                  }
                >
                  splunk syntax: {validation.splunk_syntax_validation}
                </li>
                <li className="text-warn">
                  real telemetry: {validation.real_telemetry_validation}
                </li>
              </ul>
            ) : (
              <EmptyState message="No validation provenance recorded." />
            )}
          </div>
        </div>
      </Panel>

      {references.length > 0 && (
        <Panel>
          <PanelHeader
            title={`Grounded in ${references.length} reference detection${references.length === 1 ? '' : 's'}`}
            description={
              candidate.provenance?.grounding?.knowledge_base === 'built'
                ? 'Retrieved from the knowledge base (Splunk ESCU, SigmaHQ) and approved rules.'
                : 'Retrieved from the small bundled sample. Build the full knowledge base for better grounding.'
            }
            icon={<Library className="size-4" />}
          />
          <ul className="divide-y divide-line">
            {references.map((reference) => (
              <li
                key={reference.id}
                className="flex flex-wrap items-center gap-2 px-4 py-2 text-xs"
              >
                <Badge tone={reference.source === 'approved' ? 'ok' : 'neutral'}>
                  {reference.source}
                </Badge>
                <span className="min-w-0 flex-1 truncate text-ink">{reference.title}</span>
                <span className="font-mono text-[0.68rem] text-ink-faint">
                  {reference.technique_ids.join(', ')}
                </span>
              </li>
            ))}
          </ul>
        </Panel>
      )}

      {(candidate.sigma_rule || candidate.severity || candidate.response_actions?.length) && (
        <div className="grid gap-4 lg:grid-cols-2">
          <Panel>
            <PanelHeader
              title="Sigma rule"
              description="Portable form of the same logic, for other SIEMs."
              icon={<FileCode className="size-4" />}
              actions={
                candidate.severity ? (
                  <Badge tone="neutral">severity: {candidate.severity}</Badge>
                ) : undefined
              }
            />
            <div className="space-y-3 p-4">
              <CodePanel
                code={candidate.sigma_rule ?? ''}
                language="yaml"
                maxHeight={260}
                emptyMessage="The model did not supply a Sigma rule."
              />
              {candidate.spl_from_sigma && (
                <Disclosure summary="SPL converted from the Sigma rule by pySigma">
                  <CodePanel code={candidate.spl_from_sigma} maxHeight={180} />
                </Disclosure>
              )}
            </div>
          </Panel>
          <Panel>
            <PanelHeader title="Response actions" icon={<ListChecks className="size-4" />} />
            <div className="space-y-3 p-4">
              {candidate.response_actions?.length ? (
                <ol className="list-decimal space-y-1.5 pl-5 text-xs leading-relaxed text-ink-muted">
                  {candidate.response_actions.map((action) => (
                    <li key={action}>{action}</li>
                  ))}
                </ol>
              ) : (
                <EmptyState message="No response actions were supplied." />
              )}
              {candidate.how_to_implement && (
                <div>
                  <SectionLabel>How to implement</SectionLabel>
                  <p className="text-xs leading-relaxed text-ink-muted">
                    {candidate.how_to_implement}
                  </p>
                </div>
              )}
            </div>
          </Panel>
        </div>
      )}

      {/* Static findings come from the backend, never from the model. */}
      {candidate.static_findings.length > 0 && (
        <Panel className="border-warn/30">
          <PanelHeader
            title={`Static findings (${candidate.static_findings.length})`}
            description="Deterministic checks run by IGNITE, not claims made by the model."
            icon={<TriangleAlert className="size-4 text-warn" />}
          />
          <div className="p-4">
            <List items={candidate.static_findings} empty="" />
          </div>
        </Panel>
      )}

      <div className="grid gap-4 lg:grid-cols-2">
        <Panel>
          <PanelHeader title="ATT&CK mappings" icon={<Target className="size-4" />} />
          <div className="p-4">
            {candidate.attack_mappings.length === 0 ? (
              <EmptyState message="No ATT&CK mappings were proposed for this candidate." />
            ) : (
              <ul className="space-y-3">
                {candidate.attack_mappings.map((mapping) => (
                  <li key={mapping.id} className="rounded-lg border border-line bg-raised p-3">
                    <div className="flex flex-wrap items-center gap-2">
                      <Badge tone={mapping.reference_verified ? 'primary' : 'bad'} mono>
                        {mapping.id}
                      </Badge>
                      <span className="min-w-0 flex-1 truncate text-sm text-ink">
                        {mapping.name || <span className="text-ink-faint italic">unverified</span>}
                      </span>
                      {/* ID verified and mapping evidenced are separate claims. */}
                      {mapping.mapping_supported ? (
                        <Badge tone="ok">
                          <BadgeCheck className="size-3" />
                          evidenced
                        </Badge>
                      ) : (
                        <Badge tone="warn">
                          <CircleHelp className="size-3" />
                          {mapping.reference_verified ? 'needs review' : mapping.status}
                        </Badge>
                      )}
                    </div>
                    {mapping.evidence && (
                      <p className="mt-2 text-xs leading-relaxed text-ink-muted">
                        {mapping.evidence}
                      </p>
                    )}
                    {mapping.note && (
                      <p className="mt-1.5 text-[0.7rem] leading-relaxed text-warn">
                        {mapping.note}
                      </p>
                    )}
                  </li>
                ))}
              </ul>
            )}
            <div className="mt-3 flex items-start gap-2 rounded border border-line bg-raised px-2.5 py-2 text-[0.7rem] text-ink-faint">
              <Info className="mt-0.5 size-3 shrink-0" />
              <span>
                A verified ID means the technique exists in the bundled dataset. It does not by
                itself mean this rule detects that technique.
              </span>
            </div>
          </div>
        </Panel>

        <Panel>
          <PanelHeader title="Assumed log source" icon={<Database className="size-4" />} />
          <div className="space-y-3 p-4">
            {candidate.log_source?.index || candidate.log_source?.sourcetype ? (
              <div className="space-y-1.5 font-mono text-xs">
                {candidate.log_source.index && (
                  <p className="text-accent">index = {candidate.log_source.index}</p>
                )}
                {candidate.log_source.sourcetype && (
                  <p className="text-accent">sourcetype = {candidate.log_source.sourcetype}</p>
                )}
                {candidate.log_source.event_ids?.length ? (
                  <p className="text-ink-muted">
                    event IDs: {candidate.log_source.event_ids.join(', ')}
                  </p>
                ) : null}
              </div>
            ) : (
              <EmptyState message="No log source was declared." />
            )}

            <div>
              <SectionLabel>Assumptions</SectionLabel>
              <List
                items={candidate.assumptions}
                empty="No assumptions were stated — treat the log source as unverified."
              />
            </div>
          </div>
        </Panel>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Panel>
          <PanelHeader
            title="Benign activity that would also match"
            description="Expected false positives, as proposed by the model."
            icon={<TriangleAlert className="size-4 text-warn" />}
          />
          <div className="p-4">
            <List
              items={candidate.benign_near_matches}
              empty="No benign near-matches were provided."
            />
          </div>
        </Panel>

        <Panel>
          <PanelHeader title="Blind spots" icon={<EyeOff className="size-4" />} />
          <div className="p-4">
            <List items={candidate.blind_spots} empty="No blind spots were provided." />
          </div>
        </Panel>
      </div>

      {candidate.hypothesis && (
        <Panel>
          <PanelHeader title="Detection hypothesis" icon={<Info className="size-4" />} />
          <div className="p-4">
            <p className="text-xs leading-relaxed text-ink-muted">{candidate.hypothesis}</p>
          </div>
        </Panel>
      )}
    </div>
  )
}
