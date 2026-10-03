import { useMemo, useState } from 'react'
import { AnimatePresence, motion } from 'motion/react'
import {
  ChevronLeft,
  ChevronRight,
  Clock,
  Database,
  FilePlus2,
  Grid3x3,
  Library,
  Menu,
  PanelLeft,
  ScrollText,
  Search,
  Settings2,
  Shield,
  Sparkles,
  Trash2,
  X,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Tooltip } from '@/components/ui/primitives'
import { BrandMark } from '@/components/ui/brand-mark'
import { ThemeSwitcher } from '@/components/ui/theme-switcher'
import { useReducedMotion } from '@/lib/motion'
import type { HistoryEntry } from '@/hooks/useHistory'
import type { Health } from '@/types/api'
import { cn, formatTimestamp } from '@/lib/utils'

export type View = 'generate' | 'library' | 'coverage' | 'activity' | 'platform'

export const VIEWS: { value: View; label: string; icon: typeof Sparkles }[] = [
  { value: 'generate', label: 'Generate', icon: Sparkles },
  { value: 'library', label: 'Rule Library', icon: Library },
  { value: 'coverage', label: 'ATT&CK Coverage', icon: Grid3x3 },
  { value: 'activity', label: 'Activity', icon: ScrollText },
  { value: 'platform', label: 'Platform', icon: Settings2 },
]

/** Primary navigation between the workspace and the governance views. */
function NavList({
  collapsed,
  view,
  onNavigate,
}: {
  collapsed: boolean
  view: View
  onNavigate: (view: View) => void
}) {
  return (
    <nav aria-label="Main" className="px-3 pb-3">
      <ul className="space-y-0.5">
        {VIEWS.map(({ value, label, icon: Icon }) => {
          const active = value === view
          const button = (
            <button
              onClick={() => onNavigate(value)}
              aria-current={active ? 'page' : undefined}
              aria-label={collapsed ? label : undefined}
              className={cn(
                'flex w-full items-center gap-2.5 rounded-lg border px-2.5 py-1.5 text-left text-sm',
                'transition-colors duration-[var(--dur-fast)]',
                collapsed && 'justify-center px-0',
                active
                  ? 'border-primary-line bg-primary-soft text-primary-bright'
                  : 'border-transparent text-ink-muted hover:bg-raised hover:text-ink',
              )}
            >
              <Icon className="size-4 shrink-0" aria-hidden />
              {!collapsed && <span className="truncate">{label}</span>}
            </button>
          )
          return (
            <li key={value}>{collapsed ? <Tooltip label={label}>{button}</Tooltip> : button}</li>
          )
        })}
      </ul>
    </nav>
  )
}

/** AI connection status. Reflects the real backend probe — never hardcoded. */
/** Sidebar body, shared between the desktop rail and the mobile drawer. */
function SidebarContent({
  collapsed,
  health,
  history,
  onNewAnalysis,
  onRestore,
  onClearHistory,
  activeId,
  view,
  onNavigate,
}: {
  collapsed: boolean
  health: Health | null
  history: HistoryEntry[]
  onNewAnalysis: () => void
  onRestore: (entry: HistoryEntry) => void
  onClearHistory: () => void
  activeId: string | null
  view: View
  onNavigate: (view: View) => void
}) {
  const [query, setQuery] = useState('')
  const [confirmClear, setConfirmClear] = useState(false)

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase()
    if (!needle) return history
    return history.filter((entry) => entry.description.toLowerCase().includes(needle))
  }, [history, query])

  return (
    <>
      <div className="p-3">
        {collapsed ? (
          <Tooltip label="New analysis">
            <Button
              variant="primary"
              size="icon"
              onClick={onNewAnalysis}
              aria-label="New analysis"
              className="w-full"
            >
              <FilePlus2 />
            </Button>
          </Tooltip>
        ) : (
          <Button variant="primary" className="w-full" onClick={onNewAnalysis}>
            <FilePlus2 />
            New analysis
          </Button>
        )}
      </div>

      <NavList collapsed={collapsed} view={view} onNavigate={onNavigate} />

      {!collapsed && (
        <div className="flex min-h-0 flex-1 flex-col px-3">
          <div className="mb-2 flex items-center justify-between">
            <h2 className="flex items-center gap-1.5 text-[0.66rem] font-semibold tracking-[0.09em] text-ink-faint uppercase">
              <Clock className="size-3" />
              Recent
            </h2>
            {history.length > 0 && (
              <Tooltip label="Clear history">
                <Button
                  variant="ghost"
                  size="icon"
                  className="size-6"
                  onClick={() => setConfirmClear(true)}
                  aria-label="Clear analysis history"
                >
                  <Trash2 className="size-3" />
                </Button>
              </Tooltip>
            )}
          </div>

          {/* Search appears only once the list is long enough to warrant it. */}
          {history.length > 4 && (
            <div className="relative mb-2">
              <Search
                className="pointer-events-none absolute top-1/2 left-2 size-3 -translate-y-1/2 text-ink-faint"
                aria-hidden
              />
              <input
                type="search"
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="Filter analyses"
                aria-label="Filter recent analyses"
                className="w-full rounded-lg border border-line bg-raised py-1.5 pr-2 pl-7 text-xs text-ink placeholder:text-ink-faint focus:border-primary-line focus:outline-none"
              />
            </div>
          )}

          {confirmClear ? (
            <div className="rounded-xl border border-line-strong bg-raised p-2.5">
              <p className="text-[0.7rem] leading-relaxed text-ink-muted">
                Remove all analyses stored in this browser?
              </p>
              <div className="mt-2 flex gap-1.5">
                <Button
                  variant="danger"
                  size="sm"
                  className="flex-1"
                  onClick={() => {
                    onClearHistory()
                    setConfirmClear(false)
                  }}
                >
                  Clear
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  className="flex-1"
                  onClick={() => setConfirmClear(false)}
                >
                  Cancel
                </Button>
              </div>
            </div>
          ) : history.length === 0 ? (
            <p className="px-1 text-[0.7rem] leading-relaxed text-ink-faint">
              Ready for your next investigation. Analyses you run are kept in this browser only.
            </p>
          ) : filtered.length === 0 ? (
            <p className="px-1 text-[0.7rem] text-ink-faint">No analyses match that filter.</p>
          ) : (
            <ul className="min-h-0 flex-1 space-y-0.5 overflow-y-auto pb-3">
              {filtered.map((entry) => {
                const active = entry.id === activeId
                return (
                  <li key={entry.id}>
                    <Tooltip label={entry.description}>
                      <button
                        onClick={() => onRestore(entry)}
                        aria-current={active ? 'true' : undefined}
                        className={cn(
                          'w-full rounded-lg border px-2 py-1.5 text-left',
                          'transition-colors duration-[var(--dur-fast)]',
                          active
                            ? 'border-primary-line bg-primary-soft'
                            : 'border-transparent hover:bg-raised',
                        )}
                      >
                        <span
                          className={cn(
                            'block truncate text-xs',
                            active ? 'text-primary-bright' : 'text-ink',
                          )}
                        >
                          {entry.description}
                        </span>
                        <span className="block text-[0.65rem] text-ink-faint">
                          {formatTimestamp(entry.generated_at)}
                        </span>
                      </button>
                    </Tooltip>
                  </li>
                )
              })}
            </ul>
          )}
        </div>
      )}

      {/* Engine / corpus status */}
      <div className="mt-auto border-t border-line p-3">
        {!collapsed && health && (
          <div className="mb-3 space-y-1.5">
            <div className="flex items-center gap-1.5 text-[0.68rem] text-ink-faint">
              <Database className="size-3 shrink-0" aria-hidden />
              <span>{health.mitre_techniques_loaded.toLocaleString()} ATT&amp;CK techniques</span>
            </div>
            <div className="flex items-center gap-1.5 text-[0.68rem] text-ink-faint">
              <Shield className="size-3 shrink-0" aria-hidden />
              <span>
                Sigma corpus{' '}
                <span className={health.sigma_corpus_available ? 'text-ok' : 'text-warn'}>
                  {health.sigma_corpus_available ? 'loaded' : 'empty'}
                </span>
              </span>
            </div>
          </div>
        )}
      </div>
    </>
  )
}

export function Shell({
  children,
  health,
  history,
  onNewAnalysis,
  onRestore,
  onClearHistory,
  hasAnalysis,
  activeId,
  view = 'generate',
  onNavigate = () => {},
  aiControl,
}: {
  children: React.ReactNode
  health: Health | null
  history: HistoryEntry[]
  onNewAnalysis: () => void
  onRestore: (entry: HistoryEntry) => void
  onClearHistory: () => void
  hasAnalysis: boolean
  activeId: string | null
  view?: View
  onNavigate?: (view: View) => void
  /** Header AI control; falls back to the legacy status indicator. */
  aiControl?: React.ReactNode
}) {
  const reduced = useReducedMotion()
  const [collapsed, setCollapsed] = useState(false)
  const [drawerOpen, setDrawerOpen] = useState(false)

  const sidebarProps = {
    health,
    history,
    onRestore: (entry: HistoryEntry) => {
      onRestore(entry)
      setDrawerOpen(false)
    },
    onClearHistory,
    onNewAnalysis: () => {
      onNewAnalysis()
      setDrawerOpen(false)
    },
    activeId,
    view,
    onNavigate: (next: View) => {
      onNavigate(next)
      setDrawerOpen(false)
    },
  }

  const viewLabel = VIEWS.find((item) => item.value === view)?.label ?? 'Generate'
  const subtitle: Record<View, string> = {
    generate: hasAnalysis ? 'Analysis complete' : 'Ready for your next investigation',
    library: 'Review, validate, deploy and export governed rules',
    coverage: 'Where your detections are, and where the gaps are',
    activity: 'Append-only audit trail',
    platform: 'AI provider, Splunk and governance',
  }

  return (
    <div className="flex h-screen overflow-hidden bg-canvas">
      {/* Desktop rail — a subtle background shift and one hairline, not a
          heavy outlined panel. */}
      <motion.aside
        initial={false}
        animate={{ width: collapsed ? 68 : 256 }}
        transition={reduced ? { duration: 0 } : { duration: 0.26, ease: [0.22, 1, 0.36, 1] }}
        className="relative hidden h-screen shrink-0 flex-col overflow-y-auto border-r border-line bg-surface lg:flex"
      >
        <div className="pointer-events-none absolute inset-0 bg-[image:var(--g-rail)]" aria-hidden />
        <div className="relative flex h-14 items-center gap-2.5 border-b border-line px-4">
          <BrandMark className="size-5" />
          {!collapsed && (
            <span className="truncate text-sm font-bold tracking-[0.02em] text-ink">
              IGNITE<span className="text-gradient"> 2.0</span>
            </span>
          )}
        </div>

        <div className="relative flex min-h-0 flex-1 flex-col">
          <SidebarContent collapsed={collapsed} {...sidebarProps} />
          <div className="border-t border-line p-3">
            <Tooltip label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}>
              <Button
                variant="ghost"
                size="icon"
                onClick={() => setCollapsed((c) => !c)}
                aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
                aria-expanded={!collapsed}
              >
                {collapsed ? <PanelLeft /> : <ChevronLeft />}
              </Button>
            </Tooltip>
          </div>
        </div>
      </motion.aside>

      {/* Mobile drawer */}
      <AnimatePresence>
        {drawerOpen && (
          <motion.div
            initial={reduced ? { opacity: 1 } : { opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={reduced ? { duration: 0 } : { duration: 0.18 }}
            className="fixed inset-0 z-40 bg-canvas/70 backdrop-blur-sm lg:hidden"
            onClick={() => setDrawerOpen(false)}
          >
            <motion.aside
              initial={reduced ? false : { x: -280 }}
              animate={{ x: 0 }}
              exit={reduced ? { opacity: 0 } : { x: -280 }}
              transition={reduced ? { duration: 0 } : { duration: 0.26, ease: [0.22, 1, 0.36, 1] }}
              onClick={(event) => event.stopPropagation()}
              className="flex h-full w-64 flex-col border-r border-line bg-surface"
              aria-label="Navigation"
            >
              <div className="flex h-14 items-center justify-between gap-2 border-b border-line px-4">
                <span className="flex items-center gap-2.5 text-sm font-bold text-ink">
                  <BrandMark className="size-5" />
                  IGNITE<span className="text-gradient"> 2.0</span>
                </span>
                <Button
                  variant="ghost"
                  size="icon"
                  onClick={() => setDrawerOpen(false)}
                  aria-label="Close navigation"
                >
                  <X />
                </Button>
              </div>
              <SidebarContent collapsed={false} {...sidebarProps} />
            </motion.aside>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Main column */}
      <div className="flex min-w-0 flex-1 flex-col overflow-hidden">
        <header className="z-30 flex h-14 shrink-0 items-center justify-between gap-3 border-b border-line bg-canvas/80 px-4 backdrop-blur-md sm:px-6">
          <div className="flex min-w-0 items-center gap-2">
            <Button
              variant="ghost"
              size="icon"
              className="lg:hidden"
              onClick={() => setDrawerOpen(true)}
              aria-label="Open navigation"
            >
              <Menu />
            </Button>
            <div className="min-w-0">
              <nav aria-label="Breadcrumb" className="flex items-center gap-1.5 text-sm">
                <span className="hidden text-ink-faint sm:inline">Workspace</span>
                <ChevronRight className="hidden size-3 text-ink-faint sm:inline" aria-hidden />
                <h1 className="truncate font-semibold text-ink">
                  {view === 'generate' ? 'Detection Rule Generator' : viewLabel}
                </h1>
              </nav>
              <p className="truncate text-[0.68rem] text-ink-faint">{subtitle[view]}</p>
            </div>
          </div>

          <div className="flex shrink-0 items-center gap-2">
            {aiControl}
            <ThemeSwitcher />
          </div>
        </header>

        <main className="relative mx-auto w-full max-w-[1500px] flex-1 overflow-y-auto px-4 py-6 sm:px-6">{children}</main>
      </div>

    </div>
  )
}
