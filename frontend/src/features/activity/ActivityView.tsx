import { useCallback, useEffect, useState } from 'react'
import { Download, Loader2, RefreshCw, ScrollText, TriangleAlert } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Select } from '@/components/ui/form'
import { Badge, EmptyState, Panel, PanelHeader } from '@/components/ui/primitives'
import { useToast } from '@/components/ui/toast'
import { ApiError, exportAuditCsv, listAudit } from '@/lib/api'
import { downloadText, formatTimestamp } from '@/lib/utils'
import type { AuditEntry } from '@/types/api'

const ACTIONS = [
  'saved',
  'edited',
  'approved',
  'rejected',
  'revalidated',
  'deployed',
  'deploy_failed',
  'exported',
  'deleted',
  'imported',
]

const TONE: Record<string, 'ok' | 'bad' | 'warn' | 'primary' | 'neutral'> = {
  approved: 'ok',
  deployed: 'primary',
  rejected: 'bad',
  deleted: 'bad',
  deploy_failed: 'bad',
  edited: 'warn',
}

/** The append-only audit trail: who did what to which rule, and when. */
export function ActivityView({ onOpenRule }: { onOpenRule: (id: string) => void }) {
  const toast = useToast()
  const [entries, setEntries] = useState<AuditEntry[]>([])
  const [action, setAction] = useState('')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const refresh = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      setEntries(await listAudit(action, 1000))
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'The audit log could not be loaded.')
    } finally {
      setLoading(false)
    }
  }, [action])

  useEffect(() => {
    void refresh()
  }, [refresh])

  async function handleExport() {
    try {
      const file = await exportAuditCsv()
      downloadText(file.filename, file.content, 'text/csv')
      toast(`Downloaded ${file.filename}`, 'success')
    } catch (err) {
      toast(err instanceof ApiError ? err.message : 'Export failed', 'error')
    }
  }

  return (
    <Panel>
      <PanelHeader
        title="Activity"
        description="Append-only audit log of every save, edit, review, validation, deployment, export and deletion. Entries cannot be edited or removed."
        icon={<ScrollText className="size-4" />}
        actions={
          <>
            <label htmlFor="audit-action" className="sr-only">
              Filter by action
            </label>
            <Select
              id="audit-action"
              value={action}
              onChange={(event) => setAction(event.target.value)}
              className="h-8 w-auto py-0 text-xs"
            >
              <option value="">All actions</option>
              {ACTIONS.map((item) => (
                <option key={item} value={item}>
                  {item}
                </option>
              ))}
            </Select>
            <Button variant="ghost" size="icon" aria-label="Refresh" onClick={() => void refresh()}>
              <RefreshCw />
            </Button>
            <Button variant="outline" size="sm" onClick={() => void handleExport()}>
              <Download />
              Export CSV
            </Button>
          </>
        }
      />
      {error ? (
        <div className="flex items-start gap-2 p-4 text-xs text-bad">
          <TriangleAlert className="mt-0.5 size-3.5 shrink-0" />
          {error}
        </div>
      ) : loading ? (
        <div className="flex items-center gap-2 p-4 text-xs text-ink-muted">
          <Loader2 className="size-3.5 animate-spin" />
          Loading…
        </div>
      ) : entries.length === 0 ? (
        <div className="p-4">
          <EmptyState message="No activity recorded yet." />
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[42rem] text-left text-xs">
            <thead className="border-b border-line text-[0.66rem] tracking-[0.09em] text-ink-faint uppercase">
              <tr>
                <th className="px-4 py-2 font-semibold">When</th>
                <th className="px-4 py-2 font-semibold">Who</th>
                <th className="px-4 py-2 font-semibold">Action</th>
                <th className="px-4 py-2 font-semibold">Rule</th>
                <th className="px-4 py-2 font-semibold">Detail</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {entries.map((entry) => (
                <tr key={entry.seq} className="align-top">
                  <td className="px-4 py-2 whitespace-nowrap text-ink-muted">
                    {formatTimestamp(entry.at)}
                  </td>
                  <td className="px-4 py-2 text-ink">{entry.actor}</td>
                  <td className="px-4 py-2">
                    <Badge tone={TONE[entry.action] ?? 'neutral'}>{entry.action}</Badge>
                  </td>
                  <td className="max-w-[14rem] px-4 py-2">
                    {entry.rule_id && entry.action !== 'deleted' ? (
                      <button
                        onClick={() => onOpenRule(entry.rule_id)}
                        className="truncate text-left text-primary-bright hover:underline"
                      >
                        {entry.rule_title || entry.rule_id}
                      </button>
                    ) : (
                      <span className="text-ink-muted">{entry.rule_title}</span>
                    )}
                  </td>
                  <td className="px-4 py-2 leading-relaxed break-words text-ink-muted">
                    {entry.detail}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  )
}
