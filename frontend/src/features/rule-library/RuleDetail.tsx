import { useEffect, useState } from 'react'
import {
  CircleCheck,
  CircleX,
  Download,
  FileCode,
  FlaskConical,
  Gauge,
  History,
  Loader2,
  Pencil,
  RefreshCw,
  Rocket,
  ShieldCheck,
  Target,
  Trash2,
  TriangleAlert,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { CodePanel } from '@/components/ui/code-panel'
import { Field, Select, TextArea, TextInput, lines } from '@/components/ui/form'
import {
  Badge,
  EmptyState,
  Panel,
  PanelHeader,
  SectionLabel,
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from '@/components/ui/primitives'
import {
  ChecksList,
  DeploymentBadge,
  GradeBadge,
  RuleStatusBadge,
  checkCounts,
} from '@/components/ui/quality'
import { useToast } from '@/components/ui/toast'
import {
  ApiError,
  deleteRule,
  deployRule,
  exportRule,
  getRuleVersion,
  listAudit,
  reviewRule,
  revalidateRule,
  updateRule,
} from '@/lib/api'
import { downloadText, formatTimestamp } from '@/lib/utils'
import type {
  AuditEntry,
  DeployMode,
  ExportFormat,
  LibraryRule,
  SplunkStatus,
} from '@/types/api'

const OVERRIDE_MIN = 20

function errorMessage(err: unknown, fallback: string) {
  return err instanceof ApiError ? err.message : fallback
}

function Bullets({ items, empty }: { items: string[]; empty: string }) {
  if (!items.length) return <EmptyState message={empty} />
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

/* ----------------------------------------------------------- overview */

function OverviewPanel({ rule }: { rule: LibraryRule }) {
  const counts = checkCounts(rule.validation.checks)
  return (
    <div className="space-y-4">
      {rule.deployment?.stale && (
        <div className="flex items-start gap-2 rounded-lg border border-warn/30 bg-warn-soft px-3 py-2.5 text-xs text-warn">
          <TriangleAlert className="mt-0.5 size-3.5 shrink-0" />
          <span>
            Splunk is still running version {rule.deployment.version}. This rule has changed since
            it was deployed; re-approve and redeploy to update it.
          </span>
        </div>
      )}
      {rule.provenance?.generator === 'template' && (
        <div className="rounded-lg border border-warn/30 bg-warn-soft px-3 py-2.5 text-xs text-warn">
          This rule came from a demo template, not from a model generating it for this scenario.
        </div>
      )}
      <CodePanel code={rule.spl} filename={`${rule.id}.spl`} maxHeight={260} />
      <div className="grid gap-4 lg:grid-cols-2">
        <Panel>
          <PanelHeader title="ATT&CK mapping" icon={<Target className="size-4" />} />
          <div className="p-4">
            {rule.attack_mappings.length === 0 ? (
              <EmptyState message="No technique mapped." />
            ) : (
              <ul className="space-y-2">
                {rule.attack_mappings.map((mapping) => (
                  <li key={mapping.id} className="flex flex-wrap items-center gap-2 text-xs">
                    <Badge tone={mapping.reference_verified ? 'primary' : 'bad'} mono>
                      {mapping.id}
                    </Badge>
                    <span className="min-w-0 flex-1 truncate text-ink">
                      {mapping.name || 'not in ATT&CK'}
                    </span>
                    <Badge tone={mapping.mapping_supported ? 'ok' : 'warn'}>
                      {mapping.mapping_supported ? 'evidenced' : mapping.status.replace('_', ' ')}
                    </Badge>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </Panel>
        <Panel>
          <PanelHeader
            title="Quality checks"
            description={`${counts.pass} passed · ${counts.warn} warnings · ${counts.fail} failed · ${counts.skip} skipped`}
            icon={<Gauge className="size-4" />}
            actions={
              <GradeBadge
                score={rule.validation.quality_score}
                grade={rule.validation.quality_grade}
              />
            }
          />
          <div className="max-h-72 overflow-y-auto px-4 py-1">
            <ChecksList checks={rule.validation.checks} />
          </div>
        </Panel>
      </div>
      <div className="grid gap-4 lg:grid-cols-2">
        <Panel className="p-4">
          <SectionLabel>Known false positives</SectionLabel>
          <Bullets items={rule.benign_near_matches} empty="None listed." />
        </Panel>
        <Panel className="p-4">
          <SectionLabel>Response actions</SectionLabel>
          {rule.response_actions.length ? (
            <ol className="list-decimal space-y-1.5 pl-5 text-xs leading-relaxed text-ink-muted">
              {rule.response_actions.map((action) => (
                <li key={action}>{action}</li>
              ))}
            </ol>
          ) : (
            <EmptyState message="None listed." />
          )}
        </Panel>
      </div>
      {rule.sigma_rule && (
        <CodePanel code={rule.sigma_rule} language="yaml" maxHeight={260} />
      )}
      {rule.scenario && (
        <Panel className="p-4">
          <SectionLabel>Original scenario</SectionLabel>
          <p className="text-xs leading-relaxed text-ink-muted">{rule.scenario}</p>
        </Panel>
      )}
    </div>
  )
}

/* --------------------------------------------------------------- edit */

function mappingsToText(rule: LibraryRule) {
  return rule.attack_mappings.map((m) => (m.evidence ? `${m.id} | ${m.evidence}` : m.id)).join('\n')
}

function EditPanel({
  rule,
  onSaved,
  onReload,
}: {
  rule: LibraryRule
  onSaved: (rule: LibraryRule) => void
  onReload: () => void
}) {
  const toast = useToast()
  const [form, setForm] = useState(() => ({
    title: rule.title,
    description: rule.description,
    severity: rule.severity,
    spl: rule.spl,
    sigma_rule: rule.sigma_rule,
    fps: rule.benign_near_matches.join('\n'),
    actions: rule.response_actions.join('\n'),
    how: rule.how_to_implement,
    mappings: mappingsToText(rule),
    note: '',
  }))
  const [saving, setSaving] = useState(false)
  const [conflict, setConflict] = useState<string | null>(null)

  const set = (key: keyof typeof form) => (
    event: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>,
  ) => setForm((current) => ({ ...current, [key]: event.target.value }))

  async function handleSave() {
    setSaving(true)
    setConflict(null)
    try {
      const updated = await updateRule(rule.id, {
        expected_version: rule.version,
        note: form.note,
        title: form.title,
        description: form.description,
        severity: form.severity,
        spl: form.spl,
        sigma_rule: form.sigma_rule,
        benign_near_matches: lines(form.fps),
        response_actions: lines(form.actions),
        how_to_implement: form.how,
        attack_mappings: lines(form.mappings).map((line) => {
          const [id, ...rest] = line.split('|')
          return { id: id.trim().toUpperCase(), evidence: rest.join('|').trim() }
        }),
      })
      onSaved(updated)
      toast(
        updated.version === rule.version
          ? 'Nothing changed'
          : `Saved as version ${updated.version}; checks re-run`,
        'success',
      )
    } catch (err) {
      if (err instanceof ApiError && err.status === 409) {
        setConflict(err.message)
      } else {
        toast(errorMessage(err, 'Could not save the rule'), 'error')
      }
    } finally {
      setSaving(false)
    }
  }

  return (
    <Panel>
      <PanelHeader
        title="Edit rule"
        description="Saving re-runs every check and creates a new version."
        icon={<Pencil className="size-4" />}
      />
      <div className="space-y-4 p-4">
        {rule.status === 'approved' && (
          <div className="flex items-start gap-2 rounded-md border border-warn/30 bg-warn-soft px-3 py-2 text-xs text-warn">
            <TriangleAlert className="mt-0.5 size-3.5 shrink-0" />
            <span>This rule is approved. Saving an edit returns it to draft for re-approval.</span>
          </div>
        )}
        {conflict && (
          <div className="flex flex-wrap items-center gap-2 rounded-md border border-bad/30 bg-bad-soft px-3 py-2 text-xs text-bad">
            <span className="flex-1">{conflict}</span>
            <Button variant="outline" size="sm" onClick={onReload}>
              <RefreshCw />
              Reload
            </Button>
          </div>
        )}
        <div className="grid gap-4 sm:grid-cols-[minmax(0,1fr)_10rem]">
          <Field id="edit-title" label="Title">
            <TextInput id="edit-title" value={form.title} onChange={set('title')} maxLength={200} />
          </Field>
          <Field id="edit-severity" label="Severity">
            <Select id="edit-severity" value={form.severity} onChange={set('severity')}>
              <option value="">not set</option>
              {['informational', 'low', 'medium', 'high', 'critical'].map((level) => (
                <option key={level} value={level}>
                  {level}
                </option>
              ))}
            </Select>
          </Field>
        </div>
        <Field id="edit-description" label="Description">
          <TextArea id="edit-description" rows={2} value={form.description} onChange={set('description')} />
        </Field>
        <Field id="edit-spl" label="Splunk SPL">
          <TextArea id="edit-spl" rows={5} mono value={form.spl} onChange={set('spl')} />
        </Field>
        <Field id="edit-sigma" label="Sigma rule (YAML)">
          <TextArea id="edit-sigma" rows={8} mono value={form.sigma_rule} onChange={set('sigma_rule')} />
        </Field>
        <Field
          id="edit-mappings"
          label="ATT&CK mappings"
          hint="One per line: T1059.001 | evidence from the scenario. Every ID is re-verified."
        >
          <TextArea id="edit-mappings" rows={3} mono value={form.mappings} onChange={set('mappings')} />
        </Field>
        <div className="grid gap-4 lg:grid-cols-2">
          <Field id="edit-fps" label="Known false positives" hint="One per line.">
            <TextArea id="edit-fps" rows={4} value={form.fps} onChange={set('fps')} />
          </Field>
          <Field id="edit-actions" label="Response actions" hint="One ordered step per line.">
            <TextArea id="edit-actions" rows={4} value={form.actions} onChange={set('actions')} />
          </Field>
        </div>
        <Field id="edit-how" label="How to implement">
          <TextArea id="edit-how" rows={2} value={form.how} onChange={set('how')} />
        </Field>
        <Field id="edit-note" label="Change note (recorded in the audit log)">
          <TextInput id="edit-note" value={form.note} onChange={set('note')} maxLength={500} />
        </Field>
        <Button variant="primary" onClick={() => void handleSave()} disabled={saving}>
          {saving ? <Loader2 className="animate-spin" /> : <Pencil />}
          Save changes
        </Button>
      </div>
    </Panel>
  )
}

/* ------------------------------------------------- review & deploy */

function ReviewPanel({ rule, onChange }: { rule: LibraryRule; onChange: (rule: LibraryRule) => void }) {
  const toast = useToast()
  const [note, setNote] = useState('')
  const [override, setOverride] = useState('')
  const [busy, setBusy] = useState<'approve' | 'reject' | null>(null)
  const failing = !rule.validation.passed
  const overrideShort = failing && override.trim().length < OVERRIDE_MIN

  async function decide(decision: 'approve' | 'reject') {
    setBusy(decision)
    try {
      const updated = await reviewRule(rule.id, {
        decision,
        note,
        override_justification: override,
      })
      onChange(updated)
      setNote('')
      setOverride('')
      toast(decision === 'approve' ? 'Rule approved' : 'Rule rejected', 'success')
    } catch (err) {
      toast(errorMessage(err, 'Review failed'), 'error')
    } finally {
      setBusy(null)
    }
  }

  return (
    <Panel>
      <PanelHeader
        title="Review"
        description="Only approved rules can be deployed. Approved rules also become reference examples for future generations."
        icon={<ShieldCheck className="size-4" />}
        actions={<RuleStatusBadge status={rule.status} />}
      />
      <div className="space-y-3 p-4">
        {rule.review && (
          <div className="rounded-lg border border-line bg-raised p-3 text-xs text-ink-muted">
            <p>
              <span className="font-medium text-ink">
                {rule.review.decision === 'approve' ? 'Approved' : 'Rejected'}
              </span>{' '}
              by {rule.review.by} · {formatTimestamp(rule.review.at)} · version{' '}
              {rule.review.version}
            </p>
            {rule.review.note && <p className="mt-1">“{rule.review.note}”</p>}
            {rule.review.override && (
              <p className="mt-1 text-warn">
                Override: {rule.review.override_justification}
              </p>
            )}
          </div>
        )}

        {rule.status !== 'approved' && (
          <>
            {failing && (
              <Field
                id="review-override"
                label="Override justification (required)"
                hint={`This rule fails ${rule.validation.failures.length} check(s). Explain why it is acceptable — at least ${OVERRIDE_MIN} characters. Recorded with the approval.`}
              >
                <TextArea
                  id="review-override"
                  rows={2}
                  value={override}
                  onChange={(event) => setOverride(event.target.value)}
                />
              </Field>
            )}
            <Field id="review-note" label="Review note" hint="Required when rejecting.">
              <TextArea
                id="review-note"
                rows={2}
                value={note}
                onChange={(event) => setNote(event.target.value)}
              />
            </Field>
            <div className="flex flex-wrap gap-2">
              <Button
                variant="primary"
                onClick={() => void decide('approve')}
                disabled={busy !== null || overrideShort}
              >
                {busy === 'approve' ? <Loader2 className="animate-spin" /> : <CircleCheck />}
                {failing ? 'Approve with override' : 'Approve'}
              </Button>
              <Button
                variant="danger"
                onClick={() => void decide('reject')}
                disabled={busy !== null || note.trim().length < 5}
              >
                {busy === 'reject' ? <Loader2 className="animate-spin" /> : <CircleX />}
                Reject
              </Button>
            </div>
          </>
        )}
      </div>
    </Panel>
  )
}

function TestPanel({
  rule,
  splunk,
  onChange,
}: {
  rule: LibraryRule
  splunk: SplunkStatus | null
  onChange: (rule: LibraryRule) => void
}) {
  const toast = useToast()
  const [earliest, setEarliest] = useState('-24h')
  const [busy, setBusy] = useState<'checks' | 'search' | null>(null)
  const testCheck = rule.validation.checks.find((check) => check.name === 'Test search')

  async function run(runTest: boolean) {
    setBusy(runTest ? 'search' : 'checks')
    try {
      onChange(await revalidateRule(rule.id, { run_test_search: runTest, earliest }))
      toast(runTest ? 'Test search finished' : 'Checks re-run', 'success')
    } catch (err) {
      toast(errorMessage(err, 'Validation failed'), 'error')
    } finally {
      setBusy(null)
    }
  }

  return (
    <Panel>
      <PanelHeader
        title="Validate against Splunk"
        description="Re-run every check, or run the query once over recent data to measure alert volume."
        icon={<FlaskConical className="size-4" />}
      />
      <div className="space-y-3 p-4">
        <div className="flex flex-wrap items-end gap-2">
          <Field id="test-window" label="Search window">
            <Select id="test-window" value={earliest} onChange={(e) => setEarliest(e.target.value)}>
              <option value="-1h">Last hour</option>
              <option value="-24h">Last 24 hours</option>
              <option value="-7d">Last 7 days</option>
            </Select>
          </Field>
          <Button variant="outline" onClick={() => void run(false)} disabled={busy !== null}>
            {busy === 'checks' ? <Loader2 className="animate-spin" /> : <RefreshCw />}
            Re-run checks
          </Button>
          <Button
            variant="outline"
            onClick={() => void run(true)}
            disabled={busy !== null || !splunk?.configured}
          >
            {busy === 'search' ? <Loader2 className="animate-spin" /> : <FlaskConical />}
            Run test search
          </Button>
        </div>
        {!splunk?.configured && (
          <p className="text-xs text-ink-faint">
            Splunk is not configured, so the parser check and test search are skipped. See the
            Platform page.
          </p>
        )}
        {testCheck && (
          <p className="text-xs text-ink-muted">
            <span className="font-medium text-ink">Last test search:</span> {testCheck.detail}
          </p>
        )}
      </div>
    </Panel>
  )
}

function DeployPanel({
  rule,
  splunk,
  onChange,
}: {
  rule: LibraryRule
  splunk: SplunkStatus | null
  onChange: (rule: LibraryRule) => void
}) {
  const toast = useToast()
  const [mode, setMode] = useState<DeployMode>('shadow')
  const [cron, setCron] = useState('*/15 * * * *')
  const [earliest, setEarliest] = useState('-20m')
  const [actions, setActions] = useState('')
  const [confirmLive, setConfirmLive] = useState(false)
  const [busy, setBusy] = useState(false)

  const blocked =
    rule.status !== 'approved'
      ? 'Approve the rule before deploying it.'
      : !splunk?.configured
        ? 'Splunk is not configured on the backend.'
        : ''

  async function handleDeploy() {
    if (mode === 'live' && !confirmLive) {
      setConfirmLive(true)
      return
    }
    setBusy(true)
    try {
      onChange(await deployRule(rule.id, { mode, cron, earliest, actions }))
      setConfirmLive(false)
      toast(`Deployed to Splunk as ${mode}`, 'success')
    } catch (err) {
      toast(errorMessage(err, 'Deployment failed'), 'error')
    } finally {
      setBusy(false)
    }
  }

  const modes = splunk?.deploy_modes ?? {
    disabled: 'Saved but not scheduled.',
    shadow: 'Runs on schedule; results go to Triggered Alerts only.',
    live: 'Runs on schedule and fires alert actions.',
  }

  return (
    <Panel>
      <PanelHeader
        title="Deploy to Splunk"
        description="Start in shadow mode to measure real alert volume before going live."
        icon={<Rocket className="size-4" />}
        actions={
          rule.deployment ? (
            <DeploymentBadge mode={rule.deployment.mode} stale={rule.deployment.stale} />
          ) : undefined
        }
      />
      <div className="space-y-3 p-4">
        {rule.deployment && (
          <p className="text-xs text-ink-muted">
            Saved search <span className="font-mono text-ink">{rule.deployment.name}</span> in app{' '}
            <span className="font-mono">{rule.deployment.app}</span> · {rule.deployment.mode} ·
            deployed by {rule.deployment.by} {formatTimestamp(rule.deployment.at)}
          </p>
        )}
        <fieldset className="space-y-2" disabled={Boolean(blocked)}>
          <legend className="mb-1 text-[0.68rem] font-semibold tracking-[0.09em] text-ink-faint uppercase">
            Mode
          </legend>
          {(Object.keys(modes) as DeployMode[]).map((key) => (
            <label
              key={key}
              className="flex cursor-pointer items-start gap-2 rounded-lg border border-line px-3 py-2 text-xs has-[:checked]:border-primary-line has-[:checked]:bg-primary-soft"
            >
              <input
                type="radio"
                name="deploy-mode"
                value={key}
                checked={mode === key}
                onChange={() => {
                  setMode(key)
                  setConfirmLive(false)
                }}
                className="mt-0.5 accent-[var(--c-primary)]"
              />
              <span>
                <span className="font-medium text-ink capitalize">{key}</span>
                <span className="block text-ink-muted">{modes[key]}</span>
              </span>
            </label>
          ))}
          <div className="grid gap-3 sm:grid-cols-2">
            <Field id="deploy-cron" label="Schedule (cron)">
              <TextInput id="deploy-cron" value={cron} onChange={(e) => setCron(e.target.value)} />
            </Field>
            <Field id="deploy-window" label="Search window">
              <TextInput
                id="deploy-window"
                value={earliest}
                onChange={(e) => setEarliest(e.target.value)}
              />
            </Field>
          </div>
          {mode === 'live' && (
            <Field
              id="deploy-actions"
              label="Alert actions"
              hint="Comma-separated Splunk alert action names, e.g. email,webhook."
            >
              <TextInput
                id="deploy-actions"
                value={actions}
                onChange={(e) => setActions(e.target.value)}
              />
            </Field>
          )}
        </fieldset>
        {blocked ? (
          <p className="text-xs text-warn">{blocked}</p>
        ) : (
          <>
            {confirmLive && (
              <div className="rounded-md border border-warn/30 bg-warn-soft px-3 py-2 text-xs text-warn">
                Live mode fires alert actions in production. Press Deploy again to confirm.
              </div>
            )}
            <Button variant="primary" onClick={() => void handleDeploy()} disabled={busy}>
              {busy ? <Loader2 className="animate-spin" /> : <Rocket />}
              {rule.deployment ? 'Redeploy' : 'Deploy'} as {mode}
            </Button>
          </>
        )}
      </div>
    </Panel>
  )
}

/* ------------------------------------------------------------- export */

const EXPORTS: { format: ExportFormat; label: string; description: string }[] = [
  { format: 'contentctl', label: 'contentctl YAML', description: 'Splunk detection-as-code (ESCU style)' },
  { format: 'savedsearches', label: 'savedsearches.conf', description: 'Drop-in stanza for a Splunk app' },
  { format: 'sigma', label: 'Sigma rule', description: 'Portable rule for other SIEMs' },
  { format: 'markdown', label: 'Markdown report', description: 'Review record with every check' },
  { format: 'json', label: 'JSON', description: 'The complete record' },
]

function ExportPanel({ rule }: { rule: LibraryRule }) {
  const toast = useToast()
  async function handle(format: ExportFormat) {
    try {
      const file = await exportRule(rule.id, format)
      downloadText(file.filename, file.content, file.type)
      toast(`Downloaded ${file.filename}`, 'success')
    } catch (err) {
      toast(errorMessage(err, 'Export failed'), 'error')
    }
  }
  return (
    <Panel>
      <PanelHeader title="Export" icon={<FileCode className="size-4" />} />
      <ul className="divide-y divide-line">
        {EXPORTS.map((item) => (
          <li key={item.format} className="flex flex-wrap items-center gap-3 px-4 py-2.5">
            <div className="min-w-0 flex-1">
              <p className="text-sm text-ink">{item.label}</p>
              <p className="text-xs text-ink-faint">{item.description}</p>
            </div>
            <Button
              variant="outline"
              size="sm"
              onClick={() => void handle(item.format)}
              disabled={item.format === 'sigma' && !rule.sigma_rule}
            >
              <Download />
              Download
            </Button>
          </li>
        ))}
      </ul>
    </Panel>
  )
}

/* ------------------------------------------------------------ history */

function HistoryPanel({ rule }: { rule: LibraryRule }) {
  const [entries, setEntries] = useState<AuditEntry[]>([])
  const [viewing, setViewing] = useState<LibraryRule | null>(null)

  useEffect(() => {
    listAudit('', 200, rule.id)
      .then(setEntries)
      .catch(() => setEntries([]))
  }, [rule.id, rule.updated_at])

  return (
    <div className="grid items-start gap-4 lg:grid-cols-2">
      <Panel>
        <PanelHeader title="Versions" icon={<History className="size-4" />} />
        <ul className="divide-y divide-line">
          {rule.versions.map((version) => (
            <li key={version.version} className="flex items-center gap-2 px-4 py-2 text-xs">
              <Badge tone={version.version === rule.version ? 'primary' : 'neutral'} mono>
                v{version.version}
              </Badge>
              <span className="min-w-0 flex-1 truncate text-ink-muted">
                {version.actor} · {formatTimestamp(version.saved_at)}
              </span>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => void getRuleVersion(rule.id, version.version).then(setViewing)}
              >
                View
              </Button>
            </li>
          ))}
        </ul>
        {viewing && (
          <div className="space-y-2 border-t border-line p-4">
            <SectionLabel>
              Version {viewing.version} — {viewing.title}
            </SectionLabel>
            <CodePanel code={viewing.spl} maxHeight={200} />
          </div>
        )}
      </Panel>
      <Panel>
        <PanelHeader title="Activity for this rule" icon={<History className="size-4" />} />
        {entries.length === 0 ? (
          <div className="p-4">
            <EmptyState message="No activity recorded." />
          </div>
        ) : (
          <ul className="divide-y divide-line">
            {entries.map((entry) => (
              <li key={entry.seq} className="px-4 py-2 text-xs">
                <div className="flex flex-wrap items-center gap-2">
                  <Badge tone="neutral">{entry.action}</Badge>
                  <span className="text-ink-muted">
                    {entry.actor} · {formatTimestamp(entry.at)}
                  </span>
                </div>
                {entry.detail && (
                  <p className="mt-1 leading-relaxed break-words text-ink-faint">{entry.detail}</p>
                )}
              </li>
            ))}
          </ul>
        )}
      </Panel>
    </div>
  )
}

/* -------------------------------------------------------------- detail */

export function RuleDetail({
  rule,
  splunk,
  onChange,
  onDeleted,
  onReload,
}: {
  rule: LibraryRule
  splunk: SplunkStatus | null
  onChange: (rule: LibraryRule) => void
  onDeleted: () => void
  onReload: () => void
}) {
  const toast = useToast()
  const [tab, setTab] = useState('overview')
  const [confirmDelete, setConfirmDelete] = useState(false)

  async function handleDelete() {
    try {
      await deleteRule(rule.id)
      toast('Rule deleted', 'success')
      onDeleted()
    } catch (err) {
      toast(errorMessage(err, 'Could not delete the rule'), 'error')
    }
  }

  return (
    <div className="space-y-4">
      <Panel>
        <div className="flex flex-wrap items-start justify-between gap-3 p-4">
          <div className="min-w-0">
            <h2 className="text-base font-semibold break-words text-ink">{rule.title}</h2>
            <p className="mt-1 text-xs text-ink-muted">{rule.description}</p>
            <div className="mt-2 flex flex-wrap items-center gap-1.5">
              <RuleStatusBadge status={rule.status} />
              <GradeBadge
                score={rule.validation.quality_score}
                grade={rule.validation.quality_grade}
              />
              {rule.severity && <Badge tone="neutral">severity: {rule.severity}</Badge>}
              {rule.deployment && (
                <DeploymentBadge mode={rule.deployment.mode} stale={rule.deployment.stale} />
              )}
              <Badge tone="neutral" mono>
                v{rule.version}
              </Badge>
            </div>
            <p className="mt-2 text-[0.68rem] text-ink-faint">
              Created by {rule.created_by} · {formatTimestamp(rule.created_at)} · updated{' '}
              {formatTimestamp(rule.updated_at)}
            </p>
          </div>
          {confirmDelete ? (
            <div className="flex items-center gap-1.5">
              <span className="text-xs text-bad">
                Delete permanently?{rule.deployment ? ' The Splunk saved search is not removed.' : ''}
              </span>
              <Button variant="danger" size="sm" onClick={() => void handleDelete()}>
                Delete
              </Button>
              <Button variant="ghost" size="sm" onClick={() => setConfirmDelete(false)}>
                Cancel
              </Button>
            </div>
          ) : (
            <Button
              variant="ghost"
              size="icon"
              aria-label={`Delete ${rule.title}`}
              onClick={() => setConfirmDelete(true)}
            >
              <Trash2 />
            </Button>
          )}
        </div>
      </Panel>

      <Tabs value={tab} onValueChange={setTab}>
        <TabsList aria-label="Rule views">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="edit">Edit</TabsTrigger>
          <TabsTrigger value="review">Review &amp; deploy</TabsTrigger>
          <TabsTrigger value="export">Export</TabsTrigger>
          <TabsTrigger value="history">History</TabsTrigger>
        </TabsList>
        <TabsContent value="overview">
          <OverviewPanel rule={rule} />
        </TabsContent>
        <TabsContent value="edit">
          <EditPanel
            key={`${rule.id}-${rule.version}`}
            rule={rule}
            onSaved={onChange}
            onReload={onReload}
          />
        </TabsContent>
        <TabsContent value="review">
          <div className="grid items-start gap-4 xl:grid-cols-2">
            <div className="space-y-4">
              <ReviewPanel rule={rule} onChange={onChange} />
              <TestPanel rule={rule} splunk={splunk} onChange={onChange} />
            </div>
            <DeployPanel rule={rule} splunk={splunk} onChange={onChange} />
          </div>
        </TabsContent>
        <TabsContent value="export">
          <ExportPanel rule={rule} />
        </TabsContent>
        <TabsContent value="history">
          <HistoryPanel rule={rule} />
        </TabsContent>
      </Tabs>
    </div>
  )
}
