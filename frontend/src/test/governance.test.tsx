/**
 * Tests for the merged enterprise features: quality checks on generated rules,
 * the governed rule library, ATT&CK coverage, the audit log and the platform
 * page. All network access is mocked.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ToastProvider } from '@/components/ui/toast'
import { TooltipProvider } from '@/components/ui/primitives'
import { GeneratedDetail } from '@/features/detection-rules/GeneratedDetail'
import { RuleLibraryView } from '@/features/rule-library/RuleLibraryView'
import { CoverageView } from '@/features/coverage/CoverageView'
import { ActivityView } from '@/features/activity/ActivityView'
import { PlatformView } from '@/features/platform/PlatformView'
import { toAnalysis } from '@/lib/generation'
import { AISwitcher } from '@/components/ui/ai-switcher'
import { useAIProviders } from '@/hooks/useAIProviders'
import { FIXTURE_GENERATION } from './fixtures'
import type {
  AIProviders,
  Coverage,
  GeneratedCandidate,
  GenerateRulesResult,
  LibraryRule,
  PlatformStatus,
  QualityValidation,
  RuleSummary,
  SplunkStatus,
} from '@/types/api'

function wrap(ui: React.ReactNode) {
  return render(
    <TooltipProvider>
      <ToastProvider>{ui}</ToastProvider>
    </TooltipProvider>,
  )
}

const PASSING: QualityValidation = {
  checks: [
    { name: 'SPL structure', status: 'pass', detail: 'Structure looks correct.', weight: 2 },
    { name: 'ATT&CK mapping', status: 'pass', detail: 'Verified with evidence.', weight: 2 },
    { name: 'Splunk parser', status: 'skip', detail: 'Splunk is not connected.', weight: 2 },
  ],
  passed: true,
  quality_score: 92,
  quality_grade: 'Ready',
  failures: [],
  splunk_parser: 'not_configured',
}

const FAILING: QualityValidation = {
  checks: [
    {
      name: 'SPL structure',
      status: 'fail',
      detail: "Command 'delete' modifies data or sends output — not allowed in detections.",
      weight: 2,
    },
    { name: 'SPL scope', status: 'warn', detail: 'No index.', weight: 1 },
  ],
  passed: false,
  quality_score: 33,
  quality_grade: 'Poor',
  failures: ["SPL structure: Command 'delete' modifies data"],
  splunk_parser: 'not_configured',
}

const BASE_CANDIDATE = FIXTURE_GENERATION.candidates[0] as unknown as GeneratedCandidate

function candidate(validation: QualityValidation | undefined, extra: Partial<GeneratedCandidate> = {}) {
  return { ...BASE_CANDIDATE, validation, ...extra } as GeneratedCandidate
}

function rule(overrides: Partial<LibraryRule> = {}): LibraryRule {
  return {
    id: 'r1',
    title: 'PowerShell download cradle',
    description: 'Detects PowerShell downloads.',
    scenario: 'ps cradle',
    spl: 'index=sysmon EventCode=1 | stats count by host',
    sigma_rule: '',
    spl_from_sigma: '',
    severity: 'high',
    attack_mappings: [],
    benign_near_matches: [],
    response_actions: [],
    how_to_implement: '',
    validation: PASSING,
    provenance: {},
    status: 'draft',
    review: null,
    deployment: null,
    version: 1,
    created_at: '2026-10-03T10:00:00+00:00',
    updated_at: '2026-10-03T10:00:00+00:00',
    created_by: 'analyst',
    versions: [{ version: 1, saved_at: '2026-10-03T10:00:00+00:00', actor: 'analyst' }],
    ...overrides,
  }
}

function summary(from: LibraryRule): RuleSummary {
  return {
    id: from.id,
    title: from.title,
    status: from.status,
    severity: from.severity,
    quality_score: from.validation.quality_score,
    quality_grade: from.validation.quality_grade,
    passed: from.validation.passed,
    technique_ids: [],
    deployment_mode: from.deployment?.mode ?? '',
    deployment_stale: false,
    version: from.version,
    created_at: from.created_at,
    updated_at: from.updated_at,
    created_by: from.created_by,
    demo: false,
  }
}

const SPLUNK_OFF: SplunkStatus = {
  configured: false,
  url: '',
  app: 'search',
  verify_ssl: true,
  auth: 'none',
  reachable: null,
  server: '',
  version: '',
  message: 'Splunk is not configured.',
  deploy_modes: { disabled: 'Saved only.', shadow: 'Triggered Alerts only.', live: 'Fires actions.' },
}

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status })
}

beforeEach(() => {
  vi.unstubAllGlobals()
})

/* ------------------------------------------------- generation adapter */

describe('generation adapter with quality checks', () => {
  it('uses the backend quality score when checks ran', () => {
    const result = {
      ...FIXTURE_GENERATION,
      candidates: [candidate(PASSING)],
    } as unknown as GenerateRulesResult
    const analysis = toAnalysis('scenario', result)
    expect(analysis.autonomous.quality.quality_score).toBe(92)
    expect(analysis.autonomous.validation.valid).toBe(true)
    // Checks passed out of checks that ran (the skipped parser is excluded).
    expect(analysis.autonomous.validation.score).toBe(2)
    expect(analysis.autonomous.validation.score_max).toBe(2)
  })

  it('reports Splunk parser results honestly in the status line', () => {
    const result = {
      ...FIXTURE_GENERATION,
      candidates: [candidate({ ...PASSING, splunk_parser: 'failed' })],
    } as unknown as GenerateRulesResult
    expect(toAnalysis('s', result).rule_status).toMatch(/REJECTED/)
  })
})

/* ---------------------------------------------------- generated detail */

describe('quality panel on a generated rule', () => {
  it('shows the grade and every check', () => {
    wrap(<GeneratedDetail candidate={candidate(PASSING)} scenario="s" />)
    expect(screen.getByText('92/100 · Ready')).toBeInTheDocument()
    expect(screen.getByText('Splunk parser')).toBeInTheDocument()
  })

  it('warns that a failing rule will need an override', () => {
    wrap(<GeneratedDetail candidate={candidate(FAILING)} scenario="s" />)
    expect(screen.getByText(/requires a written override justification/i)).toBeInTheDocument()
  })

  it('explains repair attempts', () => {
    const repaired = candidate(PASSING, {
      provenance: { ...BASE_CANDIDATE.provenance, repair_attempts: 1 },
    })
    wrap(<GeneratedDetail candidate={repaired} scenario="s" />)
    expect(screen.getByText(/this is repair attempt 1/i)).toBeInTheDocument()
  })

  it('saves the candidate to the library and offers to open it', async () => {
    const fetchMock = vi.fn(async (_input: string, _init?: RequestInit) => json(rule(), 201))
    vi.stubGlobal('fetch', fetchMock)
    const onSaved = vi.fn()
    const user = userEvent.setup()
    wrap(<GeneratedDetail candidate={candidate(PASSING)} scenario="the scenario" onSaved={onSaved} />)

    await user.click(screen.getByRole('button', { name: /save to rule library/i }))
    const [url, init] = fetchMock.mock.calls[0]
    expect(url).toContain('/library/rules')
    expect(JSON.parse(String(init?.body)).scenario).toBe('the scenario')

    await user.click(await screen.findByRole('button', { name: /open in library/i }))
    expect(onSaved).toHaveBeenCalledWith('r1')
  })
})

/* -------------------------------------------------------- rule library */

function mockLibrary(current: LibraryRule, onReview?: (body: Record<string, string>) => LibraryRule) {
  const fetchMock = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input)
    if (url.includes('/review')) {
      const body = JSON.parse(String(init?.body))
      return json(onReview ? onReview(body) : current)
    }
    if (url.includes('/audit')) return json([])
    if (url.match(/\/library\/rules\/r1$/)) return json(current)
    if (url.includes('/library/rules')) return json([summary(current)])
    throw new Error(`unexpected request: ${url}`)
  })
  vi.stubGlobal('fetch', fetchMock)
  return fetchMock
}

describe('rule library', () => {
  it('lists rules and opens the selected one', async () => {
    mockLibrary(rule())
    wrap(<RuleLibraryView selectedId="r1" onSelect={() => {}} splunk={SPLUNK_OFF} />)
    expect(await screen.findByRole('heading', { name: 'PowerShell download cradle' })).toBeInTheDocument()
    expect(screen.getByText('Rule library (1)')).toBeInTheDocument()
  })

  it('requires an override justification to approve a failing rule', async () => {
    mockLibrary(rule({ validation: FAILING }), (body) =>
      rule({ validation: FAILING, status: 'approved', review: {
        decision: 'approve', by: 'analyst', at: '2026-10-03T11:00:00+00:00', note: '',
        override: true, override_justification: body.override_justification, quality_score: 33, version: 1,
      } }),
    )
    const user = userEvent.setup()
    wrap(<RuleLibraryView selectedId="r1" onSelect={() => {}} splunk={SPLUNK_OFF} />)

    await user.click(await screen.findByRole('tab', { name: /review & deploy/i }))
    const approve = await screen.findByRole('button', { name: /approve with override/i })
    expect(approve).toBeDisabled()

    await user.type(
      screen.getByLabelText(/override justification/i),
      'Accepted for a contained lab exercise only.',
    )
    expect(approve).toBeEnabled()
    await user.click(approve)
    expect(await screen.findByText(/Override: Accepted for a contained lab/i)).toBeInTheDocument()
  })

  it('blocks deployment until the rule is approved and Splunk is configured', async () => {
    mockLibrary(rule())
    const user = userEvent.setup()
    wrap(<RuleLibraryView selectedId="r1" onSelect={() => {}} splunk={SPLUNK_OFF} />)
    await user.click(await screen.findByRole('tab', { name: /review & deploy/i }))
    expect(await screen.findByText('Approve the rule before deploying it.')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /run test search/i })).toBeDisabled()
  })

  it('warns when an edit will send an approved rule back to draft', async () => {
    mockLibrary(rule({ status: 'approved' }))
    const user = userEvent.setup()
    wrap(<RuleLibraryView selectedId="r1" onSelect={() => {}} splunk={SPLUNK_OFF} />)
    await user.click(await screen.findByRole('tab', { name: /^edit$/i }))
    expect(await screen.findByText(/returns it to draft for re-approval/i)).toBeInTheDocument()
  })
})

/* ------------------------------------------------------------ coverage */

const COVERAGE: Coverage = {
  tactics: [
    {
      key: 'execution',
      title: 'Execution',
      total: 2,
      covered: 1,
      coverage_pct: 50,
      techniques: [
        { id: 'T1059', name: 'Command and Scripting Interpreter', level: 'approved', rules: [{ id: 'r1', title: 'PS cradle', level: 'approved' }], rule_count: 1, references: 3 },
        { id: 'T1204', name: 'User Execution', level: null, rules: [], rule_count: 0, references: 0 },
      ],
    },
  ],
  summary: { techniques: 2, by_level: { deployed: 0, approved: 1, draft: 0, reference: 0 }, covered: 1, coverage_pct: 50 },
  attack_version: '2026-04-01T00:00:00Z',
}

describe('ATT&CK coverage', () => {
  it('shows coverage and prefills generation for a gap', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => json(COVERAGE)))
    const onGenerate = vi.fn()
    const user = userEvent.setup()
    wrap(<CoverageView onGenerate={onGenerate} />)

    expect(await screen.findByText('50%')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: /T1204/ }))
    await user.click(screen.getByRole('button', { name: /generate a detection/i }))
    expect(onGenerate).toHaveBeenCalledWith(expect.stringContaining('User Execution (MITRE ATT&CK T1204)'))
  })

  it('can hide techniques without coverage', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => json(COVERAGE)))
    const user = userEvent.setup()
    wrap(<CoverageView onGenerate={() => {}} />)
    await screen.findByText('50%')
    await user.click(screen.getByLabelText(/only techniques with coverage/i))
    expect(screen.queryByRole('button', { name: /T1204/ })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: /T1059/ })).toBeInTheDocument()
  })
})

/* -------------------------------------------------------- activity log */

describe('activity', () => {
  it('lists audit entries and links to the rule', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        json([
          { seq: 2, at: '2026-10-03T11:00:00+00:00', actor: 'analyst', action: 'approved', rule_id: 'r1', rule_title: 'PS cradle', detail: 'looks good' },
        ]),
      ),
    )
    const onOpenRule = vi.fn()
    const user = userEvent.setup()
    wrap(<ActivityView onOpenRule={onOpenRule} />)
    const row = (await screen.findByText('looks good')).closest('tr')!
    expect(within(row).getByText('approved')).toBeInTheDocument()
    await user.click(within(row).getByRole('button', { name: 'PS cradle' }))
    expect(onOpenRule).toHaveBeenCalledWith('r1')
  })
})

/* ------------------------------------------------------------ platform */

const PLATFORM: PlatformStatus = {
  provider: {
    provider: 'ollama',
    label: 'ollama',
    model: 'llama3.1',
    configured: true,
    available_providers: ['gemini', 'anthropic', 'openai', 'ollama'],
    message: '',
    data_leaves_network: false,
    generation_mode: 'gemini',
  },
  splunk: SPLUNK_OFF,
  knowledge: {
    location: 'bundled_sample',
    path: 'data/knowledge/sample',
    counts: { train: 6, val: 0, test: 3 },
    techniques_covered: 9,
    sources: {},
    approved_rules: 0,
    retrieval: 'tf-idf',
    last_evaluation: null,
  },
  library: { draft: 2, approved: 1, rejected: 0, deployed: 0 },
  operator: 'analyst',
  pysigma: true,
}

describe('platform', () => {
  it('describes the provider and Splunk status without secrets', () => {
    wrap(<PlatformView status={PLATFORM} onSplunkChecked={() => {}} />)
    expect(screen.getByText('no — local model')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /test connection/i })).toBeDisabled()
  })

  it('no longer exposes the knowledge base or evaluation internals', () => {
    wrap(<PlatformView status={PLATFORM} onSplunkChecked={() => {}} />)
    expect(screen.queryByText(/knowledge base/i)).not.toBeInTheDocument()
    expect(screen.queryByText(/python scripts\//)).not.toBeInTheDocument()
  })
})

it('saving posts nothing until asked', async () => {
  const fetchMock = vi.fn()
  vi.stubGlobal('fetch', fetchMock)
  wrap(<GeneratedDetail candidate={candidate(PASSING)} scenario="s" />)
  await waitFor(() => expect(fetchMock).not.toHaveBeenCalled())
})

/* -------------------------------------------------------- AI switcher */


const PROVIDERS: AIProviders = {
  active: 'gemini',
  env_default: 'gemini',
  overridden: false,
  options: [
    { id: 'gemini', label: 'Google Gemini', model: 'gemini-flash-latest', configured: true, ready: true, message: '', local: false, key_env: 'GEMINI_API_KEY' },
    { id: 'anthropic', label: 'Anthropic Claude', model: 'claude-opus-5-5', configured: false, ready: false, message: 'Add ANTHROPIC_API_KEY to .env and restart the API.', local: false, key_env: 'ANTHROPIC_API_KEY' },
    { id: 'ollama', label: 'Ollama (local)', model: 'qwen2.5-coder:7b-instruct', configured: true, ready: true, message: '', local: true, key_env: '' },
    { id: 'demo', label: 'Demo (no AI)', model: 'offline templates', configured: true, ready: true, message: 'No AI.', local: true, key_env: '' },
  ],
}

function SwitcherHarness() {
  const state = useAIProviders()
  return <AISwitcher state={state} />
}

describe('AI switcher', () => {
  function mockProviders() {
    let current: AIProviders = PROVIDERS
    const fetchMock = vi.fn(async (input: string, init?: RequestInit) => {
      if (input.includes('/ai/provider/reset')) {
        current = { ...PROVIDERS }
        return json(current)
      }
      if (input.includes('/ai/provider') && init?.method === 'PUT') {
        const { provider } = JSON.parse(String(init.body))
        current = { ...PROVIDERS, active: provider, overridden: provider !== 'gemini' }
        return json(current)
      }
      return json(current)
    })
    vi.stubGlobal('fetch', fetchMock)
    return fetchMock
  }

  it('shows the active AI and every choice, with unconfigured ones disabled', async () => {
    mockProviders()
    const user = userEvent.setup()
    wrap(<SwitcherHarness />)
    await user.click(await screen.findByRole('button', { name: /AI provider: Google Gemini/i }))

    expect(screen.getByRole('radio', { name: /Google Gemini/ })).toHaveAttribute('aria-checked', 'true')
    expect(screen.getByRole('radio', { name: /Anthropic Claude/ })).toBeDisabled()
    expect(screen.getByText(/Add ANTHROPIC_API_KEY to .env/)).toBeInTheDocument()
    expect(screen.getByRole('radio', { name: /Demo \(no AI\)/ })).toBeEnabled()
  })

  it('switches to Demo and offers to return to the .env default', async () => {
    const fetchMock = mockProviders()
    const user = userEvent.setup()
    wrap(<SwitcherHarness />)
    await user.click(await screen.findByRole('button', { name: /AI provider/i }))
    await user.click(screen.getByRole('radio', { name: /Demo \(no AI\)/ }))

    const put = fetchMock.mock.calls.find(([, init]) => init?.method === 'PUT')
    expect(JSON.parse(String(put?.[1]?.body))).toEqual({ provider: 'demo' })
    expect(await screen.findByRole('button', { name: /AI provider: Demo/i })).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: /AI provider: Demo/i }))
    await user.click(screen.getByRole('button', { name: /use .env default/i }))
    expect(await screen.findByRole('button', { name: /AI provider: Google Gemini/i })).toBeInTheDocument()
  })

  it('never asks for an API key', async () => {
    mockProviders()
    const user = userEvent.setup()
    wrap(<SwitcherHarness />)
    await user.click(await screen.findByRole('button', { name: /AI provider/i }))
    expect(screen.queryByRole('textbox')).not.toBeInTheDocument()
    expect(screen.getByText(/read from the backend/i)).toBeInTheDocument()
  })
})
