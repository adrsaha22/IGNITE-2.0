import { useState } from 'react'
import {
  BookOpen,
  Bot,
  CircleCheck,
  CircleDashed,
  CircleX,
  Database,
  Library,
  Loader2,
  PlugZap,
  Server,
} from 'lucide-react'
import { AIProviderList } from '@/components/ui/ai-switcher'
import { Button } from '@/components/ui/button'
import { Badge, EmptyState, Panel, PanelHeader, SectionLabel } from '@/components/ui/primitives'
import { Stat } from '@/components/ui/score'
import { useToast } from '@/components/ui/toast'
import { ApiError, checkSplunk } from '@/lib/api'
import type { AIProvidersState } from '@/hooks/useAIProviders'
import type { PlatformStatus, SplunkStatus } from '@/types/api'

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-wrap items-baseline justify-between gap-2 py-1.5 text-xs">
      <span className="text-ink-faint">{label}</span>
      <span className="min-w-0 text-right break-words text-ink">{children}</span>
    </div>
  )
}

function Ok({ ok, yes, no }: { ok: boolean | null; yes: string; no: string }) {
  if (ok === null) {
    return (
      <span className="inline-flex items-center gap-1 text-ink-muted">
        <CircleDashed className="size-3.5" /> not checked
      </span>
    )
  }
  return ok ? (
    <span className="inline-flex items-center gap-1 text-ok">
      <CircleCheck className="size-3.5" /> {yes}
    </span>
  ) : (
    <span className="inline-flex items-center gap-1 text-warn">
      <CircleX className="size-3.5" /> {no}
    </span>
  )
}

const PERCENT_KEYS = [
  ['validation_pass_rate', 'Pass all checks'],
  ['first_try_pass_rate', 'Pass first try'],
  ['mitre_exact_match', 'ATT&CK exact match'],
  ['mitre_parent_match', 'ATT&CK parent match'],
] as const

/** Integrations and data the platform depends on. Shows configuration, never secrets. */
export function PlatformView({
  status,
  onSplunkChecked,
  aiProviders,
}: {
  status: PlatformStatus | null
  onSplunkChecked: (splunk: SplunkStatus) => void
  aiProviders?: AIProvidersState
}) {
  const toast = useToast()
  const [checking, setChecking] = useState(false)

  if (!status) {
    return <EmptyState message="Platform status could not be loaded. Is the API running?" />
  }

  const { provider, splunk, knowledge, library } = status
  const evaluation = knowledge.last_evaluation

  async function handleCheck() {
    setChecking(true)
    try {
      const result = await checkSplunk()
      onSplunkChecked(result)
      toast(
        result.reachable ? `Connected to Splunk ${result.version}` : 'Splunk is not reachable',
        result.reachable ? 'success' : 'error',
      )
    } catch (err) {
      toast(err instanceof ApiError ? err.message : 'Connection test failed', 'error')
    } finally {
      setChecking(false)
    }
  }

  return (
    <div className="space-y-4">
      <Panel>
        <div className="grid grid-cols-2 gap-4 p-4 sm:grid-cols-4">
          <Stat label="Draft rules" value={library.draft} />
          <Stat label="Approved" value={library.approved} tone="primary" />
          <Stat label="Deployed" value={library.deployed} tone="accent" />
          <Stat label="Rejected" value={library.rejected} />
        </div>
      </Panel>

      <div className="grid items-start gap-4 lg:grid-cols-2">
        <Panel>
          <PanelHeader
            title="AI provider"
            description="Choose which AI to use. Keys are set in the backend .env; the default comes from IGNITE_LLM_PROVIDER."
            icon={<Bot className="size-4" />}
            actions={
              <Badge tone={provider.generation_mode === 'demo' ? 'warn' : provider.configured ? 'ok' : 'warn'}>
                {provider.generation_mode === 'demo'
                  ? 'AI off'
                  : provider.configured
                    ? 'configured'
                    : 'not configured'}
              </Badge>
            }
          />
          <div className="divide-y divide-line px-4 py-1">
            <Row label="Provider">{provider.label}</Row>
            <Row label="Model">
              <span className="font-mono">{provider.model}</span>
            </Row>
            <Row label="Generation mode">
              {provider.generation_mode === 'demo' ? 'Demo — no AI, templates only' : 'AI'}
            </Row>
            <Row label="Prompts leave your network">
              {provider.generation_mode === 'demo'
                ? 'no — AI is off'
                : provider.data_leaves_network
                  ? 'yes — hosted provider'
                  : 'no — local model'}
            </Row>
            <Row label="Supported providers">{provider.available_providers.join(', ')}</Row>
          </div>
          {provider.message && <p className="px-4 pb-3 text-xs text-warn">{provider.message}</p>}
          {aiProviders && (
            <div className="border-t border-line p-3">
              <AIProviderList state={aiProviders} />
            </div>
          )}
        </Panel>

        <Panel>
          <PanelHeader
            title="Splunk"
            description="Parser validation, test searches and deployment. Configured on the server only."
            icon={<Server className="size-4" />}
            actions={
              <Button
                variant="outline"
                size="sm"
                onClick={() => void handleCheck()}
                disabled={checking || !splunk.configured}
              >
                {checking ? <Loader2 className="animate-spin" /> : <PlugZap />}
                Test connection
              </Button>
            }
          />
          <div className="divide-y divide-line px-4 py-1">
            <Row label="Configured">
              <Ok ok={splunk.configured} yes="yes" no="no" />
            </Row>
            {splunk.configured && (
              <>
                <Row label="URL">
                  <span className="font-mono">{splunk.url}</span>
                </Row>
                <Row label="App">{splunk.app}</Row>
                <Row label="Authentication">{splunk.auth}</Row>
                <Row label="TLS verification">
                  <Ok ok={splunk.verify_ssl} yes="on" no="off (test instances only)" />
                </Row>
                <Row label="Reachable">
                  <Ok
                    ok={splunk.reachable}
                    yes={`yes · ${splunk.server} ${splunk.version}`}
                    no="no"
                  />
                </Row>
              </>
            )}
          </div>
          {splunk.message && <p className="px-4 pb-3 text-xs text-warn">{splunk.message}</p>}
        </Panel>

        <Panel>
          <PanelHeader
            title="Knowledge base"
            description="Reference detections retrieved to ground every generation."
            icon={<Database className="size-4" />}
            actions={
              <Badge tone={knowledge.location === 'built' ? 'ok' : 'warn'}>
                {knowledge.location === 'built' ? 'built' : 'bundled sample'}
              </Badge>
            }
          />
          <div className="divide-y divide-line px-4 py-1">
            {Object.entries(knowledge.counts).map(([split, count]) => (
              <Row key={split} label={`${split} examples`}>
                {count.toLocaleString()}
              </Row>
            ))}
            {knowledge.techniques_covered != null && (
              <Row label="Techniques covered">{knowledge.techniques_covered}</Row>
            )}
            <Row label="Approved rules used as references">{knowledge.approved_rules}</Row>
            <Row label="Retrieval">{knowledge.retrieval}</Row>
            <Row label="Sigma → SPL conversion">
              <Ok ok={status.pysigma} yes="pySigma installed" no="pySigma missing" />
            </Row>
          </div>
          {knowledge.location !== 'built' && (
            <div className="space-y-1 px-4 pb-3 text-xs text-ink-muted">
              <p>Build the full knowledge base from Splunk ESCU and SigmaHQ:</p>
              <pre className="overflow-x-auto rounded-md bg-canvas px-2 py-1.5 font-mono text-[0.7rem] text-ink">
                python scripts/download_sources.py{'\n'}python scripts/build_dataset.py --product windows
              </pre>
            </div>
          )}
        </Panel>

        <Panel>
          <PanelHeader
            title="Evaluation"
            description="Generation quality on techniques the retriever has never seen (scripts/evaluate.py)."
            icon={<BookOpen className="size-4" />}
          />
          {evaluation ? (
            <div className="space-y-3 p-4">
              <div className="grid grid-cols-2 gap-4">
                {PERCENT_KEYS.map(([metric, label]) => (
                  <Stat
                    key={metric}
                    label={label}
                    value={`${Math.round(Number(evaluation[metric] ?? 0) * 100)}%`}
                  />
                ))}
              </div>
              <p className="text-xs text-ink-faint">
                {String(evaluation.examples)} examples · {String(evaluation.provider)}{' '}
                {String(evaluation.model)} · average quality{' '}
                {Math.round(Number(evaluation.avg_quality_score ?? 0))}/100 ·{' '}
                {String(evaluation.evaluated_at ?? '')}
              </p>
            </div>
          ) : (
            <div className="space-y-1 p-4 text-xs text-ink-muted">
              <p>No evaluation has been run yet. It spends provider quota, so it is run on demand:</p>
              <pre className="overflow-x-auto rounded-md bg-canvas px-2 py-1.5 font-mono text-[0.7rem] text-ink">
                python scripts/evaluate.py --limit 10
              </pre>
            </div>
          )}
        </Panel>
      </div>

      <Panel className="p-4">
        <SectionLabel>Governance</SectionLabel>
        <div className="flex items-start gap-2 text-xs leading-relaxed text-ink-muted">
          <Library className="mt-0.5 size-3.5 shrink-0 text-primary-bright" />
          <p>
            Actions are recorded as <span className="font-mono text-ink">{status.operator}</span>{' '}
            (IGNITE_OPERATOR). There is no login yet, so this identifies whoever runs the API; add
            SSO before multi-user use.
          </p>
        </div>
      </Panel>
    </div>
  )
}
