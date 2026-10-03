import { useEffect, useMemo, useState } from 'react'
import { Grid3x3, Loader2, Search, Sparkles, TriangleAlert, X } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Badge, EmptyState, Panel, PanelHeader, SectionLabel } from '@/components/ui/primitives'
import { Stat } from '@/components/ui/score'
import { ApiError, getCoverage } from '@/lib/api'
import { cn } from '@/lib/utils'
import type { Coverage, CoverageLevel, CoverageTechnique } from '@/types/api'

/** Cell styling per coverage level, strongest first. Token-based for both themes. */
const LEVEL_STYLE: Record<string, string> = {
  deployed: 'border-primary bg-primary text-primary-contrast',
  approved: 'border-primary-line bg-primary-soft text-primary-bright',
  draft: 'border-line-strong bg-raised text-ink',
  reference: 'border-dashed border-line-strong bg-canvas text-ink-muted',
  none: 'border-line bg-canvas text-ink-faint',
}

const LEVEL_LABEL: Record<string, string> = {
  deployed: 'Deployed rule',
  approved: 'Approved rule',
  draft: 'Draft rule only',
  reference: 'Knowledge-base references only',
  none: 'No coverage',
}

const key = (level: CoverageLevel) => level ?? 'none'

export function CoverageView({ onGenerate }: { onGenerate: (scenario: string) => void }) {
  const [coverage, setCoverage] = useState<Coverage | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [onlyCovered, setOnlyCovered] = useState(false)
  const [query, setQuery] = useState('')
  const [selected, setSelected] = useState<CoverageTechnique | null>(null)

  useEffect(() => {
    getCoverage()
      .then(setCoverage)
      .catch((err) =>
        setError(err instanceof ApiError ? err.message : 'Coverage could not be loaded.'),
      )
  }, [])

  const columns = useMemo(() => {
    if (!coverage) return []
    const needle = query.trim().toLowerCase()
    return coverage.tactics
      .map((tactic) => ({
        ...tactic,
        techniques: tactic.techniques.filter(
          (technique) =>
            (!onlyCovered || technique.level) &&
            (!needle ||
              technique.id.toLowerCase().includes(needle) ||
              technique.name.toLowerCase().includes(needle)),
        ),
      }))
      .filter((tactic) => tactic.techniques.length > 0)
  }, [coverage, onlyCovered, query])

  if (error) {
    return (
      <Panel className="p-4">
        <div className="flex items-start gap-2 text-xs text-bad">
          <TriangleAlert className="mt-0.5 size-3.5 shrink-0" />
          {error}
        </div>
      </Panel>
    )
  }

  if (!coverage) {
    return (
      <div className="flex items-center gap-2 text-xs text-ink-muted">
        <Loader2 className="size-3.5 animate-spin" />
        Building the coverage matrix…
      </div>
    )
  }

  const { summary } = coverage

  return (
    <div className="space-y-4">
      <Panel>
        <PanelHeader
          title="ATT&CK coverage"
          description={`Enterprise techniques, coloured by your strongest coverage. Sub-techniques roll up to their parent. ATT&CK data ${coverage.attack_version.slice(0, 10)}.`}
          icon={<Grid3x3 className="size-4" />}
        />
        <div className="grid grid-cols-2 gap-4 p-4 sm:grid-cols-3 lg:grid-cols-5">
          <Stat
            label="Covered"
            value={`${summary.coverage_pct}%`}
            note={`${summary.covered} of ${summary.techniques} approved or deployed`}
            tone="primary"
          />
          <Stat label="Deployed" value={summary.by_level.deployed} note="techniques" />
          <Stat label="Approved" value={summary.by_level.approved} note="not yet deployed" />
          <Stat label="Draft only" value={summary.by_level.draft} note="awaiting review" />
          <Stat label="References only" value={summary.by_level.reference} note="gaps with examples" />
        </div>
      </Panel>

      <div className="flex flex-wrap items-center gap-3">
        <div className="relative min-w-0 flex-1 sm:max-w-xs">
          <Search
            className="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-ink-faint"
            aria-hidden
          />
          <input
            type="search"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Find a technique"
            aria-label="Find a technique"
            className="w-full rounded-lg border border-line bg-canvas py-1.5 pr-3 pl-8 text-sm text-ink placeholder:text-ink-faint focus:border-primary-line focus:outline-none"
          />
        </div>
        <label className="flex items-center gap-2 text-xs text-ink-muted">
          <input
            type="checkbox"
            checked={onlyCovered}
            onChange={(event) => setOnlyCovered(event.target.checked)}
            className="accent-[var(--c-primary)]"
          />
          Only techniques with coverage
        </label>
        <ul className="flex flex-wrap gap-3" aria-label="Legend">
          {Object.keys(LEVEL_LABEL).map((level) => (
            <li key={level} className="flex items-center gap-1.5 text-[0.7rem] text-ink-muted">
              <span className={cn('inline-block size-3 rounded-sm border', LEVEL_STYLE[level])} />
              {LEVEL_LABEL[level]}
            </li>
          ))}
        </ul>
      </div>

      {selected && (
        <Panel className="border-primary-line">
          <PanelHeader
            title={`${selected.id} · ${selected.name}`}
            description={LEVEL_LABEL[key(selected.level)]}
            icon={<Grid3x3 className="size-4" />}
            actions={
              <>
                <Button
                  variant="primary"
                  size="sm"
                  onClick={() =>
                    onGenerate(
                      `Detect ${selected.name} (MITRE ATT&CK ${selected.id}). Describe the attacker behaviour and the log source you have available here.`,
                    )
                  }
                >
                  <Sparkles />
                  Generate a detection
                </Button>
                <Button
                  variant="ghost"
                  size="icon"
                  aria-label="Close technique detail"
                  onClick={() => setSelected(null)}
                >
                  <X />
                </Button>
              </>
            }
          />
          <div className="grid gap-4 p-4 sm:grid-cols-2">
            <div>
              <SectionLabel>Your rules ({selected.rule_count})</SectionLabel>
              {selected.rules.length === 0 ? (
                <EmptyState message="No rule of yours covers this technique." />
              ) : (
                <ul className="space-y-1.5">
                  {selected.rules.map((rule) => (
                    <li key={rule.id} className="flex items-center gap-2 text-xs">
                      <Badge tone="neutral">{rule.level}</Badge>
                      <span className="truncate text-ink">{rule.title}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
            <div>
              <SectionLabel>Knowledge base</SectionLabel>
              <p className="text-xs text-ink-muted">
                {selected.references
                  ? `${selected.references} reference detection(s) will ground a new rule.`
                  : 'No reference detections; generation will rely on the model alone.'}
              </p>
            </div>
          </div>
        </Panel>
      )}

      {columns.length === 0 ? (
        <EmptyState message="No techniques match this filter." />
      ) : (
        // The matrix scrolls inside its own container, never the page.
        <div className="overflow-x-auto pb-2">
          <div className="flex min-w-max items-start gap-1.5">
            {columns.map((tactic) => (
              <section key={tactic.key} className="w-40 shrink-0" aria-label={tactic.title}>
                <header className="mb-1.5 border-b-2 border-primary-line pb-1.5">
                  <h3 className="text-xs font-semibold text-ink">{tactic.title}</h3>
                  <p className="font-mono text-[0.65rem] text-ink-faint">
                    {tactic.covered}/{tactic.total} · {tactic.coverage_pct}%
                  </p>
                </header>
                <ul className="space-y-1">
                  {tactic.techniques.map((technique) => (
                    <li key={technique.id}>
                      <button
                        onClick={() => setSelected(technique)}
                        title={`${technique.id} ${technique.name} — ${LEVEL_LABEL[key(technique.level)]}`}
                        className={cn(
                          'w-full rounded-md border px-1.5 py-1 text-left text-[0.68rem] leading-tight transition-opacity hover:opacity-80',
                          LEVEL_STYLE[key(technique.level)],
                          selected?.id === technique.id && 'ring-2 ring-primary-bright',
                        )}
                      >
                        <span className="flex items-baseline justify-between gap-1 font-mono font-semibold">
                          {technique.id}
                          {technique.rule_count > 0 && <span>{technique.rule_count}</span>}
                        </span>
                        <span className="line-clamp-2">{technique.name}</span>
                      </button>
                    </li>
                  ))}
                </ul>
              </section>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
