import { useState } from 'react'
import {
  Copy,
  Download,
  FolderOpen,
  Loader2,
  Save,
  Search,
  Trash2,
  TriangleAlert,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Badge, EmptyState, Panel, PanelHeader } from '@/components/ui/primitives'
import { useToast } from '@/components/ui/toast'
import { downloadText, fileStamp, formatTimestamp } from '@/lib/utils'
import { getInvestigation } from '@/lib/api'
import type { useInvestigations } from '@/hooks/useInvestigations'
import type { InvestigationDetail } from '@/types/api'

/**
 * Saved investigations library.
 *
 * Saving updates the currently open investigation in place, so repeated saves
 * cannot silently create duplicates.
 */
export function LibraryPanel({
  store,
  canSave,
  buildPayload,
  defaultTitle,
  onOpen,
}: {
  store: ReturnType<typeof useInvestigations>
  canSave: boolean
  buildPayload: () => Record<string, unknown>
  defaultTitle: string
  onOpen: (record: InvestigationDetail) => void
}) {
  const toast = useToast()
  const [title, setTitle] = useState('')
  const [notes, setNotes] = useState('')
  const [saving, setSaving] = useState(false)
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null)

  async function handleSave() {
    setSaving(true)
    const record = await store.save(
      title.trim() || defaultTitle,
      notes,
      buildPayload(),
    )
    setSaving(false)
    if (record) {
      setTitle(record.title)
      toast(store.currentId ? 'Investigation updated' : 'Investigation saved', 'success')
    } else {
      toast('Could not save the investigation', 'error')
    }
  }

  async function handleExport(id: string, recordTitle: string) {
    try {
      const record = await getInvestigation(id)
      downloadText(
        `ignite_investigation_${fileStamp(record.updated_at)}.json`,
        JSON.stringify(record, null, 2),
        'application/json',
      )
      toast(`Exported "${recordTitle}"`, 'success')
    } catch {
      toast('Could not export that investigation', 'error')
    }
  }

  return (
    <div className="space-y-5">
      <Panel>
        <PanelHeader
          title="Save this investigation"
          description="Stored locally on the backend, with the analysis, selected rule and test cases."
          icon={<Save className="size-4" />}
          actions={
            store.currentId ? <Badge tone="primary">Editing a saved record</Badge> : undefined
          }
        />
        <div className="space-y-3 p-4">
          {!canSave ? (
            <EmptyState message="Generate detection rules first — there is nothing to save yet." />
          ) : (
            <>
              <div>
                <label
                  htmlFor="investigation-title"
                  className="mb-1 block text-[0.68rem] font-semibold tracking-[0.09em] text-ink-faint uppercase"
                >
                  Title
                </label>
                <input
                  id="investigation-title"
                  value={title}
                  onChange={(event) => setTitle(event.target.value)}
                  placeholder={defaultTitle}
                  maxLength={200}
                  className="w-full rounded-lg border border-line bg-canvas px-3 py-2 text-sm text-ink placeholder:text-ink-faint focus:border-primary-line focus:outline-none"
                />
              </div>
              <div>
                <label
                  htmlFor="investigation-notes"
                  className="mb-1 block text-[0.68rem] font-semibold tracking-[0.09em] text-ink-faint uppercase"
                >
                  Notes (optional)
                </label>
                <textarea
                  id="investigation-notes"
                  value={notes}
                  onChange={(event) => setNotes(event.target.value)}
                  rows={3}
                  maxLength={5000}
                  placeholder="What you were investigating, what to check next…"
                  className="w-full resize-y rounded-lg border border-line bg-canvas px-3 py-2 text-sm text-ink placeholder:text-ink-faint focus:border-primary-line focus:outline-none"
                />
              </div>
              <Button variant="primary" onClick={() => void handleSave()} disabled={saving}>
                {saving ? <Loader2 className="animate-spin" /> : <Save />}
                {store.currentId ? 'Update investigation' : 'Save investigation'}
              </Button>
            </>
          )}
        </div>
      </Panel>

      <Panel>
        <PanelHeader
          title={`Saved investigations (${store.items.length})`}
          icon={<FolderOpen className="size-4" />}
        />
        <div className="space-y-3 p-4">
          <div className="relative">
            <Search
              className="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-ink-faint"
              aria-hidden
            />
            <label htmlFor="investigation-search" className="sr-only">
              Search saved investigations
            </label>
            <input
              id="investigation-search"
              type="search"
              value={store.query}
              onChange={(event) => {
                store.setQuery(event.target.value)
                void store.refresh(event.target.value)
              }}
              placeholder="Search by title or notes"
              className="w-full rounded-lg border border-line bg-canvas py-2 pr-3 pl-8 text-sm text-ink placeholder:text-ink-faint focus:border-primary-line focus:outline-none"
            />
          </div>

          {store.error && (
            <div className="flex items-start gap-2 rounded-lg border border-bad/30 bg-bad-soft px-3 py-2">
              <TriangleAlert className="mt-0.5 size-3.5 shrink-0 text-bad" />
              <p className="text-xs text-bad">{store.error}</p>
            </div>
          )}

          {store.loading ? (
            <div className="flex items-center gap-2 text-xs text-ink-muted">
              <Loader2 className="size-3.5 animate-spin text-primary-bright" />
              Loading…
            </div>
          ) : store.items.length === 0 ? (
            <EmptyState
              message={
                store.query
                  ? 'No saved investigations match that search.'
                  : 'No saved investigations yet.'
              }
            />
          ) : (
            <ul className="space-y-2">
              {store.items.map((item) => (
                <li
                  key={item.id}
                  className="rounded-lg border border-line bg-raised p-3 transition-colors hover:border-line-strong"
                >
                  <div className="flex flex-wrap items-start justify-between gap-2">
                    <div className="min-w-0">
                      <p className="truncate text-sm font-medium text-ink">{item.title}</p>
                      <p className="text-[0.68rem] text-ink-faint">
                        Updated {formatTimestamp(item.updated_at)}
                      </p>
                      {item.notes && (
                        <p className="mt-1 line-clamp-2 text-xs text-ink-muted">{item.notes}</p>
                      )}
                    </div>
                    <div className="flex shrink-0 flex-wrap gap-1">
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={async () => {
                          const record = await store.open(item.id)
                          if (record) {
                            onOpen(record)
                            setTitle(record.title)
                            setNotes(record.notes)
                            toast(`Opened "${record.title}"`, 'success')
                          }
                        }}
                      >
                        <FolderOpen />
                        Open
                      </Button>
                      <Button
                        variant="ghost"
                        size="icon"
                        aria-label={`Duplicate ${item.title}`}
                        onClick={async () => {
                          const copy = await store.duplicate(item.id)
                          if (copy) toast(`Duplicated as "${copy.title}"`, 'success')
                        }}
                      >
                        <Copy />
                      </Button>
                      <Button
                        variant="ghost"
                        size="icon"
                        aria-label={`Export ${item.title}`}
                        onClick={() => void handleExport(item.id, item.title)}
                      >
                        <Download />
                      </Button>
                      <Button
                        variant="ghost"
                        size="icon"
                        aria-label={`Delete ${item.title}`}
                        onClick={() => setConfirmDelete(item.id)}
                      >
                        <Trash2 />
                      </Button>
                    </div>
                  </div>

                  {confirmDelete === item.id && (
                    <div className="mt-3 rounded-lg border border-bad/30 bg-bad-soft p-2.5">
                      <p className="text-xs text-bad">Delete "{item.title}" permanently?</p>
                      <div className="mt-2 flex gap-1.5">
                        <Button
                          variant="danger"
                          size="sm"
                          onClick={async () => {
                            const ok = await store.remove(item.id)
                            setConfirmDelete(null)
                            toast(ok ? 'Investigation deleted' : 'Could not delete', ok ? 'success' : 'error')
                          }}
                        >
                          Delete
                        </Button>
                        <Button variant="ghost" size="sm" onClick={() => setConfirmDelete(null)}>
                          Cancel
                        </Button>
                      </div>
                    </div>
                  )}
                </li>
              ))}
            </ul>
          )}
        </div>
      </Panel>
    </div>
  )
}
