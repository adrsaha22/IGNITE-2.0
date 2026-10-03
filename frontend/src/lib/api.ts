/** HTTP client for the IGNITE 2.0 API. */

import type {
  AIChoice,
  AIProviders,
  AuditEntry,
  Coverage,
  DeployMode,
  ExportFormat,
  GeneratedCandidate,
  LibraryRule,
  PlatformStatus,
  RuleStatus,
  RuleSummary,
  RuleUpdate,
  SplunkStatus,
  AIResult,
  AIStatus,
  Analysis,
  AttackDatasetInfo,
  CopilotAction,
  CopilotContext,
  CopilotResult,
  CopilotStatus,
  CopilotTurn,
  GenerateRulesResult,
  Health,
  InvestigationDetail,
  InvestigationSummary,
  RuleTestResult,
  SampleSet,
} from '@/types/api'

/** Requests go to /api, proxied to FastAPI by Vite in development. */
const BASE = import.meta.env.VITE_API_BASE ?? '/api'

/** An API failure carrying a message safe to show a user. */
export class ApiError extends Error {
  readonly status: number

  constructor(message: string, status: number) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response
  try {
    response = await fetch(`${BASE}${path}`, {
      headers: { 'Content-Type': 'application/json' },
      ...init,
    })
  } catch {
    // Network-level failure: the API itself is unreachable.
    throw new ApiError(
      'Could not reach the IGNITE API. Check that the backend is running on port 8000.',
      0,
    )
  }

  if (!response.ok) {
    let detail = `Request failed with status ${response.status}.`
    try {
      const body = (await response.json()) as { detail?: unknown }
      if (typeof body.detail === 'string') {
        detail = body.detail
      } else if (Array.isArray(body.detail)) {
        // FastAPI validation errors arrive as an array of issues.
        detail = 'The request was rejected as invalid. Please check the values you entered.'
      }
    } catch {
      /* keep the generic message */
    }

    // A 404 on an endpoint the client knows about almost always means the
    // running backend predates the route — FastAPI's bare "Not Found" gives
    // the user nothing to act on, so say what to actually check.
    if (response.status === 404) {
      detail =
        `The API endpoint ${path} was not found (404). The running backend may be ` +
        'an older process that predates this endpoint. Restart the API server and try again.'
    }

    throw new ApiError(detail, response.status)
  }

  // 204 No Content (used by DELETE) has no body to parse.
  if (response.status === 204) {
    return undefined as T
  }

  return (await response.json()) as T
}

export function getHealth(refresh = false): Promise<Health> {
  return request<Health>(`/health${refresh ? '?refresh=true' : ''}`)
}

export function getAIStatus(refresh = false): Promise<AIStatus> {
  return request<AIStatus>(`/ai/status${refresh ? '?refresh=true' : ''}`)
}

export function analyze(description: string): Promise<Analysis> {
  return request<Analysis>('/analyze', {
    method: 'POST',
    body: JSON.stringify({ description }),
  })
}

export function aiAnalyze(description: string): Promise<AIResult> {
  return request<AIResult>('/ai/analyze', {
    method: 'POST',
    body: JSON.stringify({ description }),
  })
}

/* ------------------------------------------------------ AI Detection Assistant */

export function getCopilotStatus(): Promise<CopilotStatus> {
  return request<CopilotStatus>('/copilot/status')
}

export function askCopilot(body: {
  action: CopilotAction
  question?: string
  context?: CopilotContext
  history?: CopilotTurn[]
}): Promise<CopilotResult> {
  return request<CopilotResult>('/copilot/ask', {
    method: 'POST',
    body: JSON.stringify(body),
  })
}

/* ----------------------------------------------------- Testing Lab */

export function getSampleSets(): Promise<SampleSet[]> {
  return request<SampleSet[]>('/testlab/samples')
}

export function runRuleTest(
  rule: string,
  events: Record<string, unknown>[],
): Promise<RuleTestResult> {
  return request<RuleTestResult>('/testlab/run', {
    method: 'POST',
    body: JSON.stringify({ rule, events }),
  })
}

/* -------------------------------------------------- Investigations */

export function listInvestigations(query = ''): Promise<InvestigationSummary[]> {
  const suffix = query ? `?q=${encodeURIComponent(query)}` : ''
  return request<InvestigationSummary[]>(`/investigations${suffix}`)
}

export function getInvestigation(id: string): Promise<InvestigationDetail> {
  return request<InvestigationDetail>(`/investigations/${encodeURIComponent(id)}`)
}

export function createInvestigation(body: {
  title: string
  notes?: string
  payload: Record<string, unknown>
}): Promise<InvestigationDetail> {
  return request<InvestigationDetail>('/investigations', {
    method: 'POST',
    body: JSON.stringify(body),
  })
}

export function updateInvestigation(
  id: string,
  body: { title?: string; notes?: string; payload?: Record<string, unknown> },
): Promise<InvestigationDetail> {
  return request<InvestigationDetail>(`/investigations/${encodeURIComponent(id)}`, {
    method: 'PATCH',
    body: JSON.stringify(body),
  })
}

export function duplicateInvestigation(id: string): Promise<InvestigationDetail> {
  return request<InvestigationDetail>(
    `/investigations/${encodeURIComponent(id)}/duplicate`,
    { method: 'POST' },
  )
}

export async function deleteInvestigation(id: string): Promise<void> {
  await request<unknown>(`/investigations/${encodeURIComponent(id)}`, {
    method: 'DELETE',
  })
}

/* ------------------------------------------ LLM rule generation */

/**
 * Generate detection candidates from the scenario using the Gemini-backed
 * endpoint. A provider failure returns 200 with `ok: false` and an explicit
 * status; no template rules are ever substituted.
 */
export function generateRules(scenario: string): Promise<GenerateRulesResult> {
  return request<GenerateRulesResult>('/rules/generate', {
    method: 'POST',
    body: JSON.stringify({ scenario }),
  })
}

export function getAttackDataset(): Promise<AttackDatasetInfo> {
  return request<AttackDatasetInfo>('/attack/dataset')
}

/* ---------------------------------------------------- Rule library */

export function listRules(status: RuleStatus | '' = '', query = ''): Promise<RuleSummary[]> {
  const params = new URLSearchParams()
  if (status) params.set('status', status)
  if (query) params.set('q', query)
  const suffix = params.toString() ? `?${params}` : ''
  return request<RuleSummary[]>(`/library/rules${suffix}`)
}

export function getRule(id: string): Promise<LibraryRule> {
  return request<LibraryRule>(`/library/rules/${encodeURIComponent(id)}`)
}

export function getRuleVersion(id: string, version: number): Promise<LibraryRule> {
  return request<LibraryRule>(`/library/rules/${encodeURIComponent(id)}/versions/${version}`)
}

/** Save a generated candidate as a draft. The backend re-verifies and re-scores it. */
export function saveRule(candidate: GeneratedCandidate, scenario: string): Promise<LibraryRule> {
  return request<LibraryRule>('/library/rules', {
    method: 'POST',
    body: JSON.stringify({ candidate, scenario }),
  })
}

export function updateRule(id: string, body: RuleUpdate): Promise<LibraryRule> {
  return request<LibraryRule>(`/library/rules/${encodeURIComponent(id)}`, {
    method: 'PATCH',
    body: JSON.stringify(body),
  })
}

export function reviewRule(
  id: string,
  body: { decision: 'approve' | 'reject'; note?: string; override_justification?: string },
): Promise<LibraryRule> {
  return request<LibraryRule>(`/library/rules/${encodeURIComponent(id)}/review`, {
    method: 'POST',
    body: JSON.stringify(body),
  })
}

export function revalidateRule(
  id: string,
  body: { run_test_search: boolean; earliest?: string },
): Promise<LibraryRule> {
  return request<LibraryRule>(`/library/rules/${encodeURIComponent(id)}/revalidate`, {
    method: 'POST',
    body: JSON.stringify(body),
  })
}

export function deployRule(
  id: string,
  body: { mode: DeployMode; cron?: string; earliest?: string; actions?: string },
): Promise<LibraryRule> {
  return request<LibraryRule>(`/library/rules/${encodeURIComponent(id)}/deploy`, {
    method: 'POST',
    body: JSON.stringify(body),
  })
}

export async function deleteRule(id: string): Promise<void> {
  await request<unknown>(`/library/rules/${encodeURIComponent(id)}`, { method: 'DELETE' })
}

/** Fetch a text download, returning its suggested filename and content. */
async function download(path: string, fallbackName: string): Promise<{ filename: string; content: string; type: string }> {
  let response: Response
  try {
    response = await fetch(`${BASE}${path}`)
  } catch {
    throw new ApiError('Could not reach the IGNITE API.', 0)
  }
  if (!response.ok) {
    throw new ApiError(`Download failed with status ${response.status}.`, response.status)
  }
  const disposition = response.headers.get('Content-Disposition') ?? ''
  const match = /filename="([^"]+)"/.exec(disposition)
  return {
    filename: match?.[1] ?? fallbackName,
    content: await response.text(),
    type: response.headers.get('Content-Type') ?? 'text/plain',
  }
}

export function exportRule(id: string, format: ExportFormat) {
  return download(`/library/rules/${encodeURIComponent(id)}/export/${format}`, `rule.${format}`)
}

/* ------------------------------------------------------- Audit log */

export function listAudit(action = '', limit = 500, ruleId = ''): Promise<AuditEntry[]> {
  const params = new URLSearchParams({ limit: String(limit) })
  if (action) params.set('action', action)
  if (ruleId) params.set('rule_id', ruleId)
  return request<AuditEntry[]>(`/audit?${params}`)
}

export function exportAuditCsv() {
  return download('/audit/export.csv', 'ignite_audit.csv')
}

/* -------------------------------------------- Coverage & platform */

export function getCoverage(): Promise<Coverage> {
  return request<Coverage>('/coverage')
}

export function getPlatformStatus(): Promise<PlatformStatus> {
  return request<PlatformStatus>('/platform/status')
}

export function checkSplunk(): Promise<SplunkStatus> {
  return request<SplunkStatus>('/splunk/status?check=true')
}

/* ----------------------------------------------------- AI switcher */

export function getAIProviders(): Promise<AIProviders> {
  return request<AIProviders>('/ai/providers')
}

/** Choose the active AI. Keys stay in the backend .env; unconfigured providers are refused. */
export function setAIProvider(provider: AIChoice): Promise<AIProviders> {
  return request<AIProviders>('/ai/provider', {
    method: 'PUT',
    body: JSON.stringify({ provider }),
  })
}

export function resetAIProvider(): Promise<AIProviders> {
  return request<AIProviders>('/ai/provider/reset', { method: 'POST' })
}
