/**
 * Tests for the Gemini generation integration.
 *
 * The provider is mocked at the fetch layer; no test needs an API key or a
 * live provider. These lock in the guarantees that matter most: the primary
 * button hits the new endpoint, failures never produce candidates, and stale
 * responses cannot overwrite newer ones.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { App } from '@/app/App'
import { ToastProvider } from '@/components/ui/toast'
import { TooltipProvider } from '@/components/ui/primitives'
import { toAnalysis } from '@/lib/generation'
import {
  FIXTURE_DEMO_GENERATION,
  FIXTURE_DEMO_UNSUPPORTED,
  FIXTURE_GENERATION,
  FIXTURE_GENERATION_FAILED,
} from './fixtures'
import type { GenerateRulesResult } from '@/types/api'

const HEALTH = {
  status: 'ok',
  mitre_techniques_loaded: 697,
  sigma_corpus_available: false,
  ai: { available: true, detail: 'ready', checked_at: '2026-01-15T10:00:00Z' },
}

const COPILOT = {
  configured: true,
  model: 'gemini-flash-latest',
  provider: 'google-gemini',
  message: '',
}

/** Records every URL requested so tests can assert what was called. */
let requested: string[] = []

function mockApi(generateHandler: () => Response | Promise<Response>) {
  requested = []
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: string | URL | Request) => {
      const url = String(input)
      requested.push(url)

      if (url.includes('/health')) return new Response(JSON.stringify(HEALTH), { status: 200 })
      if (url.includes('/copilot/status'))
        return new Response(JSON.stringify(COPILOT), { status: 200 })
      if (url.includes('/testlab/samples')) return new Response('[]', { status: 200 })
      if (url.includes('/investigations')) return new Response('[]', { status: 200 })
      if (url.includes('/rules/generate')) return generateHandler()

      throw new Error(`unexpected request: ${url}`)
    }),
  )
}

function ok(body: unknown = FIXTURE_GENERATION) {
  return () => new Response(JSON.stringify(body), { status: 200 })
}

function renderApp() {
  return render(
    <TooltipProvider>
      <ToastProvider>
        <App />
      </ToastProvider>
    </TooltipProvider>,
  )
}

async function generate(user: ReturnType<typeof userEvent.setup>, text = 'powershell attack') {
  await user.type(screen.getByLabelText(/attack scenario description/i), text)
  await user.click(screen.getByRole('button', { name: /generate detection rules/i }))
}

beforeEach(() => {
  localStorage.clear()
  vi.restoreAllMocks()
})

/* ------------------------------------------------ successful generation */

describe('successful generation', () => {
  it('calls /api/rules/generate, not the legacy /api/analyze', async () => {
    mockApi(ok())
    const user = userEvent.setup()
    renderApp()
    await generate(user)

    await waitFor(() => expect(screen.getAllByRole('tab').length).toBeGreaterThan(0))
    expect(requested.some((u) => u.includes('/rules/generate'))).toBe(true)
    // The legacy endpoint must not be touched by the primary workflow.
    expect(requested.some((u) => /\/api\/analyze$/.test(u))).toBe(false)
  })

  it('sends the user\'s actual scenario text', async () => {
    mockApi(ok())
    const user = userEvent.setup()
    renderApp()
    await generate(user, 'certutil downloaded an encoded payload')

    await waitFor(() => expect(screen.getAllByRole('tab').length).toBeGreaterThan(0))
    const call = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls.find((c) =>
      String(c[0]).includes('/rules/generate'),
    )
    expect(JSON.parse(String(call?.[1]?.body)).scenario).toBe(
      'certutil downloaded an encoded payload',
    )
  })

  it('populates the candidate list from the response', async () => {
    mockApi(ok())
    const user = userEvent.setup()
    renderApp()
    await generate(user)

    await user.click(await screen.findByRole('tab', { name: /detection rules/i }))
    const group = await screen.findByRole('radiogroup', { name: /candidate detection rules/i })
    expect(group).toBeInTheDocument()
    expect(await screen.findByText(/Candidates \(2\)/)).toBeInTheDocument()
  })

  it('shows the generated SPL of the selected candidate', async () => {
    mockApi(ok())
    const user = userEvent.setup()
    renderApp()
    await generate(user)

    await waitFor(() => expect(screen.getAllByRole('tab').length).toBeGreaterThan(0))
    const code = document.querySelector('pre code')
    expect(code?.textContent).toContain('CommandLine="*DownloadString*"')
  })

  it('labels the result as LLM-generated and not Splunk validated', async () => {
    mockApi(ok())
    const user = userEvent.setup()
    renderApp()
    await generate(user)

    await user.click(await screen.findByRole('tab', { name: /detection rules/i }))
    expect(await screen.findAllByText(/LLM-generated/i)).not.toHaveLength(0)
    expect(screen.getAllByText(/not_configured/i).length).toBeGreaterThan(0)
  })
})

/* ---------------------------------------------------------- failures */

describe('generation failures', () => {
  it('shows an actionable message when no API key is configured', async () => {
    mockApi(ok(FIXTURE_GENERATION_FAILED))
    const user = userEvent.setup()
    renderApp()
    await generate(user)

    expect(await screen.findByText(/AI menu in the header/)).toBeInTheDocument()
    // No candidates may be shown.
    expect(screen.queryAllByRole('tab')).toHaveLength(0)
  })

  it('surfaces a provider 503 without fabricating candidates', async () => {
    mockApi(
      ok({
        ...FIXTURE_GENERATION_FAILED,
        status: 'provider_error',
        message: 'The provider returned an error.',
      }),
    )
    const user = userEvent.setup()
    renderApp()
    await generate(user)

    expect(await screen.findByText(/provider returned an error/i)).toBeInTheDocument()
    expect(screen.queryAllByRole('tab')).toHaveLength(0)
  })

  it('surfaces a rate limit distinctly', async () => {
    mockApi(
      ok({ ...FIXTURE_GENERATION_FAILED, status: 'rate_limited', message: 'Quota reached.' }),
    )
    const user = userEvent.setup()
    renderApp()
    await generate(user)

    expect(await screen.findByText(/rate limit was reached/i)).toBeInTheDocument()
  })

  it('handles a network failure', async () => {
    mockApi(() => {
      throw new TypeError('network down')
    })
    const user = userEvent.setup()
    renderApp()
    await generate(user)

    expect(await screen.findByText(/could not reach the ignite api/i)).toBeInTheDocument()
    expect(screen.queryAllByRole('tab')).toHaveLength(0)
  })

  it('treats an empty candidate list as a failure, not a success', async () => {
    mockApi(ok({ ...FIXTURE_GENERATION, candidates: [] }))
    const user = userEvent.setup()
    renderApp()
    await generate(user)

    expect(await screen.findByText(/no detection candidates/i)).toBeInTheDocument()
    expect(screen.queryAllByRole('tab')).toHaveLength(0)
  })

  it('never falls back to the legacy endpoint on failure', async () => {
    mockApi(ok(FIXTURE_GENERATION_FAILED))
    const user = userEvent.setup()
    renderApp()
    await generate(user)

    await screen.findByText(/AI menu in the header/)
    expect(requested.some((u) => /\/api\/analyze$/.test(u))).toBe(false)
  })
})

/* ------------------------------------------------------ state correctness */

describe('state correctness', () => {
  it('prevents duplicate submissions while a request is in flight', async () => {
    let resolve: (r: Response) => void = () => {}
    mockApi(() => new Promise<Response>((r) => (resolve = r)))

    const user = userEvent.setup()
    renderApp()
    await generate(user)

    // Further clicks while loading must not issue more requests.
    const button = screen.getByRole('button', { name: /analysing/i })
    await user.click(button).catch(() => {})

    const generateCalls = requested.filter((u) => u.includes('/rules/generate'))
    expect(generateCalls).toHaveLength(1)

    resolve(new Response(JSON.stringify(FIXTURE_GENERATION), { status: 200 }))
  })

  it('clears stale candidates when a later attempt fails', async () => {
    let call = 0
    mockApi(() => {
      call += 1
      return new Response(
        JSON.stringify(call === 1 ? FIXTURE_GENERATION : FIXTURE_GENERATION_FAILED),
        { status: 200 },
      )
    })

    const user = userEvent.setup()
    renderApp()
    await generate(user)
    await waitFor(() => expect(screen.getAllByRole('tab').length).toBeGreaterThan(0))

    await user.click(screen.getByRole('button', { name: /generate detection rules/i }))

    // The earlier candidates were not produced by this run, so they must go.
    await waitFor(() => expect(screen.queryAllByRole('tab')).toHaveLength(0))
  })

  it('shows a loading state during generation', async () => {
    let resolve: (r: Response) => void = () => {}
    mockApi(() => new Promise<Response>((r) => (resolve = r)))

    const user = userEvent.setup()
    renderApp()
    await generate(user)

    expect(screen.getByRole('button', { name: /analysing/i })).toBeDisabled()
    resolve(new Response(JSON.stringify(FIXTURE_GENERATION), { status: 200 }))
  })
})

/* -------------------------------------------------- adapter guarantees */

describe('generation adapter', () => {
  const result = FIXTURE_GENERATION as unknown as GenerateRulesResult

  it('does not fabricate validation or quality scores', () => {
    const analysis = toAnalysis('scenario', result)
    // The LLM path runs no scoring heuristic; null means "not scored".
    expect(analysis.autonomous.validation.score).toBeNull()
    expect(analysis.autonomous.quality.quality_score).toBeNull()
    expect(analysis.autonomous.validation.valid).toBeNull()
  })

  it('never claims Splunk or telemetry validation', () => {
    const analysis = toAnalysis('scenario', result)
    expect(analysis.rule_status).toContain('not validated against a live Splunk instance')
  })

  it('only lists techniques whose ID was verified', () => {
    const analysis = toAnalysis('scenario', result)
    const ids = analysis.autonomous.techniques.map((t) => t.id)
    expect(ids).toContain('T1059.001')
    // The invented ID must not appear as a mapped technique.
    expect(ids).not.toContain('T9999.999')
  })

  it('surfaces unverified mappings as warnings instead', () => {
    const analysis = toAnalysis('scenario', result)
    expect(
      analysis.warnings.some((w) => w.includes('T9999.999') && w.includes('could not be verified')),
    ).toBe(true)
  })

  it('surfaces backend static findings as warnings', () => {
    const analysis = toAnalysis('scenario', result)
    expect(analysis.warnings.some((w) => w.includes('matches every value'))).toBe(true)
  })

  it('preserves per-candidate detail against the right candidate', () => {
    const analysis = toAnalysis('scenario', result)
    expect(analysis.generation.candidates).toHaveLength(2)
    expect(analysis.generation.candidates[0]!.assumptions).toContain(
      'Sysmon EventCode 1 is collected',
    )
    // The second candidate has its own, different findings.
    expect(analysis.generation.candidates[1]!.static_findings).not.toHaveLength(0)
  })

  it('keeps candidate SPL distinct per candidate', () => {
    const analysis = toAnalysis('scenario', result)
    expect(analysis.candidates[0]!.spl).not.toBe(analysis.candidates[1]!.spl)
  })
})

/* ------------------------------------ route/transport failures */

describe('transport failures are distinguished from provider failures', () => {
  it('surfaces a 404 as a route problem, not a Gemini failure', async () => {
    // Regression: a stale backend process that predates the route returned
    // FastAPI's bare {"detail":"Not Found"}, which the UI showed as
    // "Not Found" with no guidance.
    mockApi(() => new Response(JSON.stringify({ detail: 'Not Found' }), { status: 404 }))
    const user = userEvent.setup()
    renderApp()
    await generate(user)

    const message = await screen.findByText(/was not found \(404\)/i)
    expect(message).toBeInTheDocument()
    // It must point at the real cause: a stale server.
    expect(screen.getByText(/restart the api server/i)).toBeInTheDocument()
    // And must not be blamed on the provider.
    expect(screen.queryByText(/rate limit/i)).not.toBeInTheDocument()
    expect(screen.queryByText(/GEMINI_API_KEY/)).not.toBeInTheDocument()
  })

  it('names the missing endpoint in the 404 message', async () => {
    mockApi(() => new Response(JSON.stringify({ detail: 'Not Found' }), { status: 404 }))
    const user = userEvent.setup()
    renderApp()
    await generate(user)

    expect(await screen.findByText(/\/rules\/generate/)).toBeInTheDocument()
  })

  it('surfaces a provider 503 as a provider failure, not a route error', async () => {
    mockApi(
      ok({
        ...FIXTURE_GENERATION_FAILED,
        status: 'provider_error',
        message: 'The provider returned an error.',
      }),
    )
    const user = userEvent.setup()
    renderApp()
    await generate(user)

    expect(await screen.findByText(/provider returned an error/i)).toBeInTheDocument()
    expect(screen.queryByText(/was not found \(404\)/i)).not.toBeInTheDocument()
    expect(screen.queryByText(/restart the api server/i)).not.toBeInTheDocument()
  })

  it('shows zero candidates for any failure mode', async () => {
    const failures = [
      () => new Response(JSON.stringify({ detail: 'Not Found' }), { status: 404 }),
      ok({ ...FIXTURE_GENERATION_FAILED, status: 'provider_error' }),
      ok({ ...FIXTURE_GENERATION_FAILED, status: 'rate_limited' }),
    ]
    for (const handler of failures) {
      mockApi(handler)
      const user = userEvent.setup()
      const view = renderApp()
      await generate(user)
      await waitFor(() => expect(screen.queryAllByRole('tab')).toHaveLength(0))
      view.unmount()
    }
  })

  it('retrying issues a new request and can recover', async () => {
    let call = 0
    mockApi(() => {
      call += 1
      // First attempt 404s (stale server); after a restart it succeeds.
      return call === 1
        ? new Response(JSON.stringify({ detail: 'Not Found' }), { status: 404 })
        : new Response(JSON.stringify(FIXTURE_GENERATION), { status: 200 })
    })

    const user = userEvent.setup()
    renderApp()
    await generate(user)
    await screen.findByText(/was not found \(404\)/i)

    await user.click(screen.getByRole('button', { name: /try again/i }))

    await waitFor(() => expect(screen.getAllByRole('tab').length).toBeGreaterThan(0))
    expect(requested.filter((u) => u.includes('/rules/generate'))).toHaveLength(2)
  })
})

/* --------------------------------------------- offline demo mode */

describe('demo mode labelling', () => {
  it('labels a demo candidate as template-based, never as LLM output', async () => {
    mockApi(ok(FIXTURE_DEMO_GENERATION))
    const user = userEvent.setup()
    renderApp()
    await generate(user)

    await user.click(await screen.findByRole('tab', { name: /detection rules/i }))

    expect(await screen.findByText(/DEMO · template-based/i)).toBeInTheDocument()
    // The LLM badge must not appear for template output.
    expect(screen.queryByText(/^LLM-generated$/)).not.toBeInTheDocument()
  })

  it('warns that a demo rule is not model-generated or Splunk validated', async () => {
    mockApi(ok(FIXTURE_DEMO_GENERATION))
    const user = userEvent.setup()
    renderApp()
    await generate(user)

    await user.click(await screen.findByRole('tab', { name: /detection rules/i }))
    const warning = await screen.findByText(/pre-written demo template/i)
    expect(warning).toBeInTheDocument()
    expect(warning.textContent).toMatch(/not been validated against Splunk/i)
    expect(warning.textContent).toMatch(/not evidence that this attack would be detected/i)
  })

  it('shows no provider or model for demo output', async () => {
    mockApi(ok(FIXTURE_DEMO_GENERATION))
    const user = userEvent.setup()
    renderApp()
    await generate(user)

    await user.click(await screen.findByRole('tab', { name: /detection rules/i }))
    const provenance = await screen.findByText(/offline template · no provider/i)
    expect(provenance).toBeInTheDocument()

    // The provenance panel must not attribute this candidate to a model. The
    // Copilot's own status badge names a model independently, so scope the
    // check to the provenance block.
    const panel = provenance.closest('div')?.parentElement
    expect(panel?.textContent).not.toMatch(/gemini/i)
  })

  it('carries the DEMO prefix in the candidate name', async () => {
    mockApi(ok(FIXTURE_DEMO_GENERATION))
    const user = userEvent.setup()
    renderApp()
    await generate(user)

    expect(await screen.findAllByText(/\[DEMO\]/)).not.toHaveLength(0)
  })

  it('surfaces an unsupported-scenario refusal with zero candidates', async () => {
    mockApi(ok(FIXTURE_DEMO_UNSUPPORTED))
    const user = userEvent.setup()
    renderApp()
    await generate(user)

    expect(await screen.findByText(/no template covering this scenario/i)).toBeInTheDocument()
    // No unrelated rule is shown in its place.
    expect(screen.queryAllByRole('tab')).toHaveLength(0)
  })
})
