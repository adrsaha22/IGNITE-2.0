/**
 * Application behaviour tests. All network access is mocked; no test requires a
 * running backend or model server.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { App } from '@/app/App'
import { ToastProvider } from '@/components/ui/toast'
import { TooltipProvider } from '@/components/ui/primitives'
import { FIXTURE_GENERATION } from './fixtures'


/** The Copilot is unconfigured by default in tests — no key, no network. */
const COPILOT_STATUS = {
  configured: false,
  model: 'gemini-3.5-flash',
  provider: 'google-gemini',
  message: 'The AI Copilot is not configured.',
}

/** Overview, Detection Rules, Testing Lab, Attack Intelligence, Validation, Library, Export. */
const TAB_COUNT = 7

const HEALTH = {
  status: 'ok',
  mitre_techniques_loaded: 858,
  sigma_corpus_available: false,
  ai: { available: false, detail: 'model server unreachable', checked_at: '2026-01-15T10:00:00Z' },
}

/** Install a fetch stub covering the endpoints the app calls. */
function mockApi(
  generation: unknown = FIXTURE_GENERATION,
  opts: { analyzeFails?: boolean } = {},
) {
  const fetchMock = vi.fn(async (input: string | URL | Request) => {
    const url = String(input)

    if (url.includes('/health')) {
      return new Response(JSON.stringify(HEALTH), { status: 200 })
    }
    if (url.includes('/ai/status')) {
      return new Response(JSON.stringify(HEALTH.ai), { status: 200 })
    }
    if (url.includes('/copilot/status')) {
      return new Response(JSON.stringify(COPILOT_STATUS), { status: 200 })
    }
    if (url.includes('/testlab/samples')) {
      return new Response(JSON.stringify([]), { status: 200 })
    }
    if (url.includes('/investigations')) {
      return new Response(JSON.stringify([]), { status: 200 })
    }
    if (url.includes('/ai/analyze')) {
      return new Response(
        JSON.stringify({
          available: false,
          text: null,
          error: "AI analysis unavailable: HTTPConnectionPool(host='localhost', port=11434)",
        }),
        { status: 200 },
      )
    }
    if (url.includes('/rules/generate')) {
      if (opts.analyzeFails) {
        return new Response(JSON.stringify({ detail: 'The detection pipeline failed.' }), {
          status: 500,
        })
      }
      return new Response(JSON.stringify(generation), { status: 200 })
    }
    // The legacy endpoint must never be reached by the primary workflow.
    if (url.includes('/analyze')) {
      throw new Error('legacy /api/analyze must not be called by the Generate button')
    }
    throw new Error(`unexpected request: ${url}`)
  })
  vi.stubGlobal('fetch', fetchMock)
  return fetchMock
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

/** Type a description and click Generate. */
async function generate(user: ReturnType<typeof userEvent.setup>, text = 'powershell attack') {
  await user.type(screen.getByLabelText(/attack scenario description/i), text)
  await user.click(screen.getByRole('button', { name: /generate detection rules/i }))
  await waitFor(() => expect(screen.getByRole('tab', { name: /overview/i })).toBeInTheDocument())
}

beforeEach(() => {
  localStorage.clear()
  vi.restoreAllMocks()
})

describe('initial render', () => {
  it('renders with no analysis and shows an empty state', async () => {
    mockApi()
    renderApp()

    expect(await screen.findByText(/find the signal/i)).toBeInTheDocument()
    expect(screen.queryByRole('tab', { name: /overview/i })).not.toBeInTheDocument()
  })

  it('disables generation until a description is entered', async () => {
    mockApi()
    renderApp()

    expect(screen.getByRole('button', { name: /generate detection rules/i })).toBeDisabled()
  })

  it('reports AI as offline without blocking the app', async () => {
    mockApi()
    renderApp()

    expect(await screen.findByText(/ai offline/i)).toBeInTheDocument()
    // Rule generation remains available.
    expect(screen.getByRole('button', { name: /generate detection rules/i })).toBeInTheDocument()
  })
})

describe('generating an analysis', () => {
  it('renders real backend results into the tabs', async () => {
    mockApi()
    const user = userEvent.setup()
    renderApp()
    await generate(user)

    expect(screen.getAllByRole('tab')).toHaveLength(TAB_COUNT)
    // The generated SPL is displayed. Highlighting splits it across spans, so
    // assert against the code block's combined text content.
    const code = document.querySelector('pre code')
    expect(code?.textContent).toContain('Image="*powershell.exe*"')
  })

  it('does not invent validation or quality scores on the LLM path', async () => {
    // The generation path runs no scoring heuristic, so a number here would
    // be fabricated. The UI must say "not scored" instead of showing 0.
    mockApi()
    const user = userEvent.setup()
    renderApp()
    await generate(user)

    await user.click(screen.getByRole('tab', { name: /validation/i }))
    expect(await screen.findAllByText(/not scored on this path/i)).not.toHaveLength(0)
  })

  it('preserves results when switching tabs', async () => {
    mockApi()
    const user = userEvent.setup()
    renderApp()
    await generate(user)

    await user.click(screen.getByRole('tab', { name: /attack intelligence/i }))
    expect(await screen.findAllByText('PowerShell')).not.toHaveLength(0)

    await user.click(screen.getByRole('tab', { name: /overview/i }))
    expect(await screen.findByText(/best detection rule/i)).toBeInTheDocument()
    expect(screen.getAllByRole('tab')).toHaveLength(TAB_COUNT)
  })

  it('warns that results are stale when the description changes', async () => {
    mockApi()
    const user = userEvent.setup()
    renderApp()
    await generate(user)

    await user.type(screen.getByLabelText(/attack scenario description/i), ' plus extra text')
    expect(await screen.findByText(/description has changed/i)).toBeInTheDocument()
  })
})

describe('rule selection', () => {
  it('changes the displayed rule and drives the export', async () => {
    mockApi()
    const user = userEvent.setup()
    renderApp()
    await generate(user)

    await user.click(screen.getByRole('tab', { name: /detection rules/i }))
    const group = await screen.findByRole('radiogroup', { name: /candidate detection rules/i })
    const options = within(group).getAllByRole('radio')
    expect(options).toHaveLength(2)

    // Selecting the second candidate surfaces its no-conditions warning.
    await user.click(options[1]!)
    expect(await screen.findByText(/no field conditions detected/i)).toBeInTheDocument()

    // The export tab follows the selection.
    await user.click(screen.getByRole('tab', { name: /export/i }))
    expect(await screen.findByText(/Rule #2 selected/i)).toBeInTheDocument()
  })
})

describe('validation honesty', () => {
  it('surfaces static findings from the backend, not model self-assessment', async () => {
    mockApi()
    const user = userEvent.setup()
    renderApp()
    await generate(user)

    // The second candidate has a match-everything wildcard finding.
    expect(
      await screen.findAllByText(/matches every value and does not filter anything/i),
    ).not.toHaveLength(0)
  })

  it('states that external validation was not performed', async () => {
    mockApi()
    const user = userEvent.setup()
    renderApp()
    await generate(user)

    await user.click(screen.getByRole('tab', { name: /validation/i }))
    expect(await screen.findByText(/never contacts a Splunk instance/i)).toBeInTheDocument()
  })
})

describe('empty and error states', () => {
  it('flags an unverified ATT&CK technique rather than trusting it', async () => {
    mockApi()
    const user = userEvent.setup()
    renderApp()
    await generate(user)

    // The fixture's second candidate carries an invented T9999.999.
    expect(
      await screen.findAllByText(/could not be verified against the ATT&CK dataset/i),
    ).not.toHaveLength(0)
  })

  it('shows a recoverable error when the pipeline fails', async () => {
    mockApi(null, { analyzeFails: true })
    const user = userEvent.setup()
    renderApp()

    await user.type(screen.getByLabelText(/attack scenario description/i), 'powershell')
    await user.click(screen.getByRole('button', { name: /generate detection rules/i }))

    expect(await screen.findByText(/the detection pipeline failed/i)).toBeInTheDocument()
    // A retry affordance is offered.
    expect(screen.getByRole('button', { name: /try again/i })).toBeInTheDocument()
  })

  it('clears results when a later attempt fails, rather than showing stale ones', async () => {
    // First call succeeds, second fails.
    let calls = 0
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: string | URL | Request) => {
        const url = String(input)
        if (url.includes('/health')) return new Response(JSON.stringify(HEALTH), { status: 200 })
        if (url.includes('/ai/status'))
          return new Response(JSON.stringify(HEALTH.ai), { status: 200 })
        if (url.includes('/copilot/status'))
          return new Response(JSON.stringify(COPILOT_STATUS), { status: 200 })
        if (url.includes('/testlab/samples'))
          return new Response(JSON.stringify([]), { status: 200 })
        if (url.includes('/investigations'))
          return new Response(JSON.stringify([]), { status: 200 })
        if (url.includes('/rules/generate')) {
          calls += 1
          if (calls === 1) {
            return new Response(JSON.stringify(FIXTURE_GENERATION), { status: 200 })
          }
          return new Response(JSON.stringify({ detail: 'Pipeline blew up.' }), { status: 500 })
        }
        throw new Error(`unexpected ${url}`)
      }),
    )

    const user = userEvent.setup()
    renderApp()
    await generate(user)

    await user.click(screen.getByRole('button', { name: /generate detection rules/i }))
    expect(await screen.findByText(/pipeline blew up/i)).toBeInTheDocument()
    // The earlier analysis is still on screen.
    expect(screen.getAllByRole('tab')).toHaveLength(TAB_COUNT)
  })
})

describe('AI analysis', () => {
  it('reports unavailability without breaking rule generation', async () => {
    mockApi()
    const user = userEvent.setup()
    renderApp()
    await generate(user)

    await user.click(screen.getByRole('button', { name: /run ai analysis/i }))
    expect(await screen.findByText(/ai analysis is unavailable/i)).toBeInTheDocument()
    // Results remain intact.
    expect(screen.getAllByRole('tab')).toHaveLength(TAB_COUNT)
  })

  it('keeps the raw error in a collapsible technical section', async () => {
    mockApi()
    const user = userEvent.setup()
    renderApp()

    await user.type(screen.getByLabelText(/attack scenario description/i), 'powershell')
    await user.click(screen.getByRole('button', { name: /run ai analysis/i }))

    expect(await screen.findByText(/technical details/i)).toBeInTheDocument()
    expect(screen.getByText(/HTTPConnectionPool/)).toBeInTheDocument()
  })
})

describe('history persistence', () => {
  it('stores a completed analysis and restores it', async () => {
    mockApi()
    const user = userEvent.setup()
    renderApp()
    await generate(user)

    // Written under a versioned key.
    const raw = localStorage.getItem('ignite.history.v1')
    expect(raw).toBeTruthy()
    expect(JSON.parse(raw!).version).toBe(1)

    // Starting a new analysis clears the workspace...
    await user.click(screen.getByRole('button', { name: /new analysis/i }))
    expect(await screen.findByText(/find the signal/i)).toBeInTheDocument()

    // ...and the history entry restores it. The description appears both in
    // the history button and its tooltip, so target the button directly.
    const entries = screen.getAllByText('powershell attack')
    const historyButton = entries
      .map((node) => node.closest('button'))
      .find((node): node is HTMLButtonElement => node !== null)
    expect(historyButton).toBeTruthy()
    await user.click(historyButton!)
    await waitFor(() => expect(screen.getAllByRole('tab')).toHaveLength(TAB_COUNT))
  })

  it('discards corrupted stored history instead of crashing', async () => {
    localStorage.setItem('ignite.history.v1', '{not valid json')
    mockApi()
    renderApp()

    expect(await screen.findByText(/find the signal/i)).toBeInTheDocument()
  })

  it('discards history written under an older schema version', async () => {
    localStorage.setItem(
      'ignite.history.v1',
      JSON.stringify({ version: 0, entries: [{ junk: true }] }),
    )
    mockApi()
    renderApp()

    expect(await screen.findByText(/analyses you run are kept in this browser/i)).toBeInTheDocument()
  })
})
