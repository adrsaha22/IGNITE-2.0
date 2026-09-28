import {
  BadgeCheck,
  Bot,
  CircleHelp,
  Database,
  EyeOff,
  FlaskConical,
  Info,
  Target,
  TriangleAlert,
} from 'lucide-react'
import { Badge, EmptyState, Panel, PanelHeader, SectionLabel } from '@/components/ui/primitives'
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
export function GeneratedDetail({ candidate }: { candidate: GeneratedCandidate }) {
  const validation = candidate.provenance?.validation
  // Demo candidates are pre-written templates, not model output. The label
  // must make that unmistakable wherever provenance is shown.
  const isDemo = candidate.provenance?.generator === 'template'

  return (
    <div className="space-y-4">
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
                <li className="text-ink-muted">
                  local sample test: {validation.local_sample_test}
                </li>
                <li className="text-warn">
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
