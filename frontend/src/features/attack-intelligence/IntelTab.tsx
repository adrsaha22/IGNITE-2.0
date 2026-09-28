import { Binary, Database, FileSearch, Hammer, Crosshair, Info } from 'lucide-react'
import { Badge, EmptyState, Panel, PanelHeader, SectionLabel } from '@/components/ui/primitives'
import type { Analysis } from '@/types/api'

function BadgeGroup({
  values,
  empty,
  tone = 'neutral',
  mono = false,
}: {
  values: (string | number)[]
  empty: string
  tone?: 'primary' | 'accent' | 'neutral'
  mono?: boolean
}) {
  if (values.length === 0) return <EmptyState message={empty} />
  return (
    <div className="flex flex-wrap gap-1.5">
      {values.map((value) => (
        <Badge key={String(value)} tone={tone} mono={mono}>
          {value}
        </Badge>
      ))}
    </div>
  )
}

/** Structured, human-readable intelligence. Nothing is shown that the pipeline
 *  does not actually produce — notably tactics, which it does not map. */
export function IntelTab({ analysis }: { analysis: Analysis }) {
  const { autonomous: auto, entities } = analysis
  const telemetry = auto.telemetry

  return (
    <div className="space-y-5">
      <div className="grid gap-4 lg:grid-cols-2">
        <Panel>
          <PanelHeader
            title="ATT&CK techniques"
            description="Names resolved from the bundled ATT&CK dataset."
            icon={<Crosshair className="size-4" />}
          />
          <div className="p-4">
            {auto.techniques.length === 0 ? (
              <EmptyState message="No techniques were mapped from this description." />
            ) : (
              <ul className="divide-y divide-line">
                {auto.techniques.map((technique) => (
                  <li key={technique.id} className="flex items-center gap-3 py-2.5 first:pt-0">
                    <Badge tone="primary" mono>
                      {technique.id}
                    </Badge>
                    <span className="min-w-0 flex-1 truncate text-sm text-ink">
                      {technique.name || (
                        <span className="text-ink-faint italic">name unavailable</span>
                      )}
                    </span>
                  </li>
                ))}
              </ul>
            )}
            <div className="mt-3 flex items-start gap-2 rounded border border-line bg-raised px-2.5 py-2 text-[0.7rem] text-ink-faint">
              <Info className="mt-0.5 size-3 shrink-0" />
              <span>
                Tactic mappings are not shown because the current detection pipeline does not
                produce them.
              </span>
            </div>
          </div>
        </Panel>

        <Panel>
          <PanelHeader
            title="Extracted entities"
            description="Derived from the attack description by keyword extraction."
            icon={<FileSearch className="size-4" />}
          />
          <div className="space-y-4 p-4">
            <div>
              <SectionLabel>
                <Hammer className="mr-1 inline size-3" /> Tools
              </SectionLabel>
              <BadgeGroup values={entities.tools} empty="No tools extracted." tone="primary" mono />
            </div>
            <div>
              <SectionLabel>
                <Binary className="mr-1 inline size-3" /> Indicators
              </SectionLabel>
              <BadgeGroup values={entities.indicators} empty="No indicators extracted." mono />
            </div>
            <div>
              <SectionLabel>
                <Database className="mr-1 inline size-3" /> Log sources
              </SectionLabel>
              <BadgeGroup values={entities.logs} empty="No log sources extracted." />
            </div>
            <div>
              <SectionLabel>Fields referenced</SectionLabel>
              <BadgeGroup values={entities.fields} empty="No fields extracted." tone="accent" mono />
            </div>
          </div>
        </Panel>
      </div>

      <Panel>
        <PanelHeader
          title="Telemetry requirements"
          description="Data the mapped techniques need in order to be detectable."
          icon={<Database className="size-4" />}
        />
        <div className="grid gap-4 p-4 sm:grid-cols-3">
          <div>
            <SectionLabel>Event codes</SectionLabel>
            <BadgeGroup values={telemetry.events} empty="None listed." tone="accent" mono />
          </div>
          <div>
            <SectionLabel>Log sources</SectionLabel>
            <BadgeGroup values={telemetry.logs} empty="None listed." />
          </div>
          <div>
            <SectionLabel>Fields</SectionLabel>
            <BadgeGroup values={telemetry.fields} empty="None listed." tone="accent" mono />
          </div>
        </div>
      </Panel>

      <Panel>
        <PanelHeader title="Detection rationale" icon={<Info className="size-4" />} />
        <div className="p-4">
          {auto.explanation.trim() ? (
            <pre className="font-sans text-xs leading-relaxed whitespace-pre-wrap text-ink-muted">
              {auto.explanation}
            </pre>
          ) : (
            <EmptyState message="No explanation was generated for this analysis." />
          )}
        </div>
      </Panel>
    </div>
  )
}
