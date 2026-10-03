import { useCallback, useEffect, useState } from 'react'
import { Library, Loader2, Search, TriangleAlert } from 'lucide-react'
import { EmptyState, Panel, PanelHeader } from '@/components/ui/primitives'
import { DeploymentBadge, GradeBadge, RuleStatusBadge } from '@/components/ui/quality'
import { ApiError, getRule, listRules } from '@/lib/api'
import { cn, formatTimestamp } from '@/lib/utils'
import type { LibraryRule, RuleStatus, RuleSummary, SplunkStatus } from '@/types/api'
import { RuleDetail } from './RuleDetail'

const FILTERS: { value: RuleStatus | ''; label: string }[] = [
  { value: '', label: 'All' },
  { value: 'draft', label: 'Draft' },
  { value: 'approved', label: 'Approved' },
  { value: 'rejected', label: 'Rejected' },
]

/**
 * The governed rule library: generated candidates become drafts here, are
 * reviewed, validated against Splunk, deployed, exported and audited.
 */
export function RuleLibraryView({
  selectedId,
  onSelect,
  splunk,
}: {
  selectedId: string | null
  onSelect: (id: string | null) => void
  splunk: SplunkStatus | null
}) {
  const [rules, setRules] = useState<RuleSummary[]>([])
  const [status, setStatus] = useState<RuleStatus | ''>('')
  const [query, setQuery] = useState('')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [detail, setDetail] = useState<LibraryRule | null>(null)
  const [detailError, setDetailError] = useState<string | null>(null)

  const refresh = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      setRules(await listRules(status, query))
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'The rule library could not be loaded.')
    } finally {
      setLoading(false)
    }
  }, [status, query])

  useEffect(() => {
    void refresh()
  }, [refresh])

  const loadDetail = useCallback(async (id: string) => {
    setDetailError(null)
    try {
      setDetail(await getRule(id))
    } catch (err) {
      setDetail(null)
      setDetailError(err instanceof ApiError ? err.message : 'The rule could not be loaded.')
    }
  }, [])

  useEffect(() => {
    if (selectedId) void loadDetail(selectedId)
    else setDetail(null)
  }, [selectedId, loadDetail])

  const handleChange = (rule: LibraryRule) => {
    setDetail(rule)
    void refresh()
  }

  return (
    <div className="grid items-start gap-4 lg:grid-cols-[minmax(0,20rem)_minmax(0,1fr)]">
      <Panel className="overflow-hidden">
        <PanelHeader
          title={`Rule library (${rules.length})`}
          description="Generated rules move through review before deployment."
          icon={<Library className="size-4" />}
        />
        <div className="space-y-2 border-b border-line p-3">
          <div className="flex flex-wrap gap-1" role="group" aria-label="Filter by status">
            {FILTERS.map((filter) => (
              <button
                key={filter.label}
                onClick={() => setStatus(filter.value)}
                aria-pressed={status === filter.value}
                className={cn(
                  'rounded-md border px-2 py-1 text-xs transition-colors',
                  status === filter.value
                    ? 'border-primary-line bg-primary-soft text-primary-bright'
                    : 'border-line text-ink-muted hover:bg-raised',
                )}
              >
                {filter.label}
              </button>
            ))}
          </div>
          <div className="relative">
            <Search
              className="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-ink-faint"
              aria-hidden
            />
            <input
              type="search"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search title or technique"
              aria-label="Search rules"
              className="w-full rounded-lg border border-line bg-canvas py-1.5 pr-3 pl-8 text-sm text-ink placeholder:text-ink-faint focus:border-primary-line focus:outline-none"
            />
          </div>
        </div>
        {error && (
          <div className="flex items-start gap-2 p-3 text-xs text-bad">
            <TriangleAlert className="mt-0.5 size-3.5 shrink-0" />
            {error}
          </div>
        )}
        {loading ? (
          <div className="flex items-center gap-2 p-4 text-xs text-ink-muted">
            <Loader2 className="size-3.5 animate-spin" />
            Loading…
          </div>
        ) : rules.length === 0 ? (
          <div className="p-3">
            <EmptyState
              message={
                status || query
                  ? 'No rules match this filter.'
                  : 'No rules yet. Generate detections and choose "Save to rule library".'
              }
            />
          </div>
        ) : (
          <ul className="max-h-[70vh] divide-y divide-line overflow-y-auto">
            {rules.map((rule) => (
              <li key={rule.id}>
                <button
                  onClick={() => onSelect(rule.id)}
                  aria-current={rule.id === selectedId ? 'true' : undefined}
                  className={cn(
                    'w-full px-3.5 py-2.5 text-left transition-colors',
                    rule.id === selectedId ? 'bg-primary-soft' : 'hover:bg-raised',
                  )}
                >
                  <span className="block truncate text-xs font-medium text-ink">{rule.title}</span>
                  <span className="mt-1.5 flex flex-wrap items-center gap-1">
                    <RuleStatusBadge status={rule.status} />
                    <GradeBadge score={rule.quality_score} grade={rule.quality_grade} />
                    <DeploymentBadge mode={rule.deployment_mode} stale={rule.deployment_stale} />
                  </span>
                  <span className="mt-1 block truncate font-mono text-[0.65rem] text-ink-faint">
                    {rule.technique_ids.join(', ') || 'no technique'} · v{rule.version} ·{' '}
                    {formatTimestamp(rule.updated_at)}
                  </span>
                </button>
              </li>
            ))}
          </ul>
        )}
      </Panel>

      <div className="min-w-0">
        {detailError ? (
          <EmptyState message={detailError} />
        ) : detail ? (
          <RuleDetail
            key={detail.id}
            rule={detail}
            splunk={splunk}
            onChange={handleChange}
            onReload={() => void loadDetail(detail.id)}
            onDeleted={() => {
              onSelect(null)
              void refresh()
            }}
          />
        ) : (
          <Panel className="p-6">
            <EmptyState message="Select a rule to review, validate, deploy or export it." />
          </Panel>
        )}
      </div>
    </div>
  )
}
