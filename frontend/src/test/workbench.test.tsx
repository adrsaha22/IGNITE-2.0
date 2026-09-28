/**
 * Tests for the Copilot, Testing Lab and Library features.
 * All network access is mocked; nothing here reaches a provider or a backend.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { CopilotPanel } from '@/features/copilot/CopilotPanel'
import { TestLabTab } from '@/features/testlab/TestLabTab'
import { LibraryPanel } from '@/features/library/LibraryPanel'
import { ToastProvider } from '@/components/ui/toast'
import { TooltipProvider } from '@/components/ui/primitives'
import { FIXTURE_ANALYSIS } from './fixtures'
import type { CopilotStatus, InvestigationSummary } from '@/types/api'

const CONFIGURED: CopilotStatus = {
  configured: true,
  model: 'gemini-3.5-flash',
  provider: 'google-gemini',
  message: '',
}

const UNCONFIGURED: CopilotStatus = {
  configured: false,
  model: 'gemini-3.5-flash',
  provider: 'google-gemini',
  message: 'The AI Copilot is not configured. Set GEMINI_API_KEY.',
}

function wrap(node: React.ReactNode) {
  return render(
    <TooltipProvider>
      <ToastProvider>{node}</ToastProvider>
    </TooltipProvider>,
  )
}

/** Route fetch calls to per-endpoint handlers. */
function mockFetch(handlers: Record<string, () => Response>) {
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: string | URL | Request) => {
      const url = String(input)
      for (const [fragment, handler] of Object.entries(handlers)) {
        if (url.includes(fragment)) return handler()
      }
      throw new Error(`unexpected request: ${url}`)
    }),
  )
}

beforeEach(() => {
  vi.restoreAllMocks()
})

/* ------------------------------------------------------- AI Copilot */

describe('Copilot', () => {
  it('shows a configuration hint when no API key is set', async () => {
    mockFetch({
      '/copilot/status': () => new Response(JSON.stringify(UNCONFIGURED), { status: 200 }),
    })
    wrap(<CopilotPanel analysis={FIXTURE_ANALYSIS} selectedIndex={0} />)

    // Shown both as a status badge and as an actionable warning.
    expect(await screen.findAllByText(/not configured/i)).toHaveLength(2)
    expect(screen.getByText(/GEMINI_API_KEY/)).toBeInTheDocument()
  })

  it('states that rule generation works without the Copilot', async () => {
    mockFetch({
      '/copilot/status': () => new Response(JSON.stringify(UNCONFIGURED), { status: 200 }),
    })
    wrap(<CopilotPanel analysis={FIXTURE_ANALYSIS} selectedIndex={0} />)

    expect(await screen.findByText(/work without it/i)).toBeInTheDocument()
  })

  it('disables the actions while unconfigured', async () => {
    mockFetch({
      '/copilot/status': () => new Response(JSON.stringify(UNCONFIGURED), { status: 200 }),
    })
    wrap(<CopilotPanel analysis={FIXTURE_ANALYSIS} selectedIndex={0} />)

    await screen.findAllByText(/not configured/i)
    expect(screen.getByRole('button', { name: /explain this rule/i })).toBeDisabled()
  })

  it('renders a successful answer and labels it AI-generated', async () => {
    mockFetch({
      '/copilot/status': () => new Response(JSON.stringify(CONFIGURED), { status: 200 }),
      '/copilot/ask': () =>
        new Response(
          JSON.stringify({
            ok: true,
            status: 'ok',
            text: 'Summary:\nDetects PowerShell downloads.',
            sections: [{ heading: 'Summary', body: 'Detects PowerShell downloads.' }],
            message: '',
            model: 'gemini-3.5-flash',
            ai_generated: true,
          }),
          { status: 200 },
        ),
    })

    const user = userEvent.setup()
    wrap(<CopilotPanel analysis={FIXTURE_ANALYSIS} selectedIndex={0} />)

    await waitFor(() =>
      expect(screen.getByRole('button', { name: /explain this rule/i })).toBeEnabled(),
    )
    await user.click(screen.getByRole('button', { name: /explain this rule/i }))

    expect(await screen.findByText(/Detects PowerShell downloads/)).toBeInTheDocument()
    expect(screen.getByText(/AI-generated/)).toBeInTheDocument()
    // Users are told the output may be wrong.
    expect(screen.getByText(/AI output can be wrong/i)).toBeInTheDocument()
  })

  it('surfaces a rate-limit failure with a retry action', async () => {
    mockFetch({
      '/copilot/status': () => new Response(JSON.stringify(CONFIGURED), { status: 200 }),
      '/copilot/ask': () =>
        new Response(
          JSON.stringify({
            ok: false,
            status: 'rate_limited',
            text: '',
            sections: [],
            message: "The provider's rate limit was reached.",
            model: '',
            ai_generated: true,
          }),
          { status: 200 },
        ),
    })

    const user = userEvent.setup()
    wrap(<CopilotPanel analysis={FIXTURE_ANALYSIS} selectedIndex={0} />)

    await waitFor(() =>
      expect(screen.getByRole('button', { name: /explain this rule/i })).toBeEnabled(),
    )
    await user.click(screen.getByRole('button', { name: /explain this rule/i }))

    expect(await screen.findByText(/rate limit was reached/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /retry/i })).toBeInTheDocument()
  })

  it('never renders fabricated text on failure', async () => {
    mockFetch({
      '/copilot/status': () => new Response(JSON.stringify(CONFIGURED), { status: 200 }),
      '/copilot/ask': () =>
        new Response(
          JSON.stringify({
            ok: false,
            status: 'unreachable',
            text: '',
            sections: [],
            message: 'The provider could not be reached.',
            model: '',
            ai_generated: true,
          }),
          { status: 200 },
        ),
    })

    const user = userEvent.setup()
    wrap(<CopilotPanel analysis={FIXTURE_ANALYSIS} selectedIndex={0} />)

    await waitFor(() =>
      expect(screen.getByRole('button', { name: /explain this rule/i })).toBeEnabled(),
    )
    await user.click(screen.getByRole('button', { name: /explain this rule/i }))

    await screen.findByText(/could not be reached/i)
    expect(screen.queryByText(/AI-generated/)).not.toBeInTheDocument()
  })

  it('sends only bounded context, not the whole analysis', async () => {
    const calls: string[] = []
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
        const url = String(input)
        if (url.includes('/copilot/status')) {
          return new Response(JSON.stringify(CONFIGURED), { status: 200 })
        }
        calls.push(String(init?.body ?? ''))
        return new Response(
          JSON.stringify({
            ok: true,
            status: 'ok',
            text: 'x',
            sections: [],
            message: '',
            model: 'm',
            ai_generated: true,
          }),
          { status: 200 },
        )
      }),
    )

    const user = userEvent.setup()
    wrap(<CopilotPanel analysis={FIXTURE_ANALYSIS} selectedIndex={0} />)

    await waitFor(() =>
      expect(screen.getByRole('button', { name: /explain this rule/i })).toBeEnabled(),
    )
    await user.click(screen.getByRole('button', { name: /explain this rule/i }))

    await waitFor(() => expect(calls.length).toBe(1))
    const sent = JSON.parse(calls[0]!)
    expect(Object.keys(sent.context).sort()).toEqual([
      'entities',
      'quality',
      'rule',
      'rule_origin',
      'scenario',
      'techniques',
      'validation_issues',
    ])
    // Internal result fields are not forwarded.
    expect(calls[0]).not.toContain('sigma_references')
  })
})

/* ------------------------------------------------------ Testing Lab */

describe('Testing Lab', () => {
  const noop = () => {}

  it('states that matching is local, not Splunk', () => {
    mockFetch({ '/testlab/samples': () => new Response('[]', { status: 200 }) })
    wrap(
      <TestLabTab
        analysis={FIXTURE_ANALYSIS}
        selectedIndex={0}
        testCases={[]}
        onTestCasesChange={noop}
      />,
    )
    expect(screen.getByText(/local SPL subset/i)).toBeInTheDocument()
    expect(screen.getByText(/not by Splunk/i)).toBeInTheDocument()
  })

  it('shows an empty state with no test events', () => {
    mockFetch({ '/testlab/samples': () => new Response('[]', { status: 200 }) })
    wrap(
      <TestLabTab
        analysis={FIXTURE_ANALYSIS}
        selectedIndex={0}
        testCases={[]}
        onTestCasesChange={noop}
      />,
    )
    expect(screen.getByText(/No test events yet/i)).toBeInTheDocument()
  })

  it('reports invalid JSON rather than running the test', async () => {
    mockFetch({ '/testlab/samples': () => new Response('[]', { status: 200 }) })
    const user = userEvent.setup()
    wrap(
      <TestLabTab
        analysis={FIXTURE_ANALYSIS}
        selectedIndex={0}
        testCases={[{ id: '1', label: 'bad', json: '{not json' }]}
        onTestCasesChange={noop}
      />,
    )

    await user.click(screen.getByRole('button', { name: /run local test/i }))
    expect(await screen.findByText(/not valid JSON/i)).toBeInTheDocument()
  })

  it('renders match results and unsupported constructs', async () => {
    mockFetch({
      '/testlab/samples': () => new Response('[]', { status: 200 }),
      '/testlab/run': () =>
        new Response(
          JSON.stringify({
            supported: true,
            results: [
              {
                event_id: 'e1',
                outcome: 'match',
                observations: [
                  {
                    field: 'Image',
                    operator: '=',
                    expected: '*powershell*',
                    actual: 'powershell.exe',
                    matched: true,
                    missing: false,
                  },
                ],
                missing_fields: [],
                reason: 'All testable conditions matched.',
              },
            ],
            unsupported: ['transforming command `| stats` (not evaluated)'],
            referenced_fields: ['Image'],
            error: '',
            matched_count: 1,
            total_count: 1,
            validation_mode: 'local_sample',
            disclaimer: 'Evaluated by IGNITE, not by Splunk.',
          }),
          { status: 200 },
        ),
    })

    const user = userEvent.setup()
    wrap(
      <TestLabTab
        analysis={FIXTURE_ANALYSIS}
        selectedIndex={0}
        testCases={[{ id: '1', label: 'e1', json: '{"Image":"powershell.exe"}' }]}
        onTestCasesChange={noop}
      />,
    )

    await user.click(screen.getByRole('button', { name: /run local test/i }))

    expect(await screen.findByText(/1 of 1 matched/i)).toBeInTheDocument()
    expect(screen.getByText(/Not applied by the local evaluator/i)).toBeInTheDocument()
    expect(screen.getByText(/\| stats/)).toBeInTheDocument()
  })

  it('reports a rule the evaluator cannot test', async () => {
    mockFetch({
      '/testlab/samples': () => new Response('[]', { status: 200 }),
      '/testlab/run': () =>
        new Response(
          JSON.stringify({
            supported: false,
            results: [],
            unsupported: [],
            referenced_fields: [],
            error: 'No testable field conditions were found in this rule.',
            matched_count: 0,
            total_count: 0,
            validation_mode: 'local_sample',
            disclaimer: 'd',
          }),
          { status: 200 },
        ),
    })

    const user = userEvent.setup()
    wrap(
      <TestLabTab
        analysis={FIXTURE_ANALYSIS}
        selectedIndex={0}
        testCases={[{ id: '1', label: 'e1', json: '{}' }]}
        onTestCasesChange={noop}
      />,
    )

    await user.click(screen.getByRole('button', { name: /run local test/i }))
    expect(await screen.findByText(/No testable field conditions/i)).toBeInTheDocument()
    expect(screen.getByText(/Not evaluable/i)).toBeInTheDocument()
  })
})

/* --------------------------------------------------------- Library */

const SAVED: InvestigationSummary[] = [
  {
    id: 'inv-1',
    title: 'PowerShell staging',
    notes: 'initial triage',
    created_at: '2026-01-15T10:00:00+00:00',
    updated_at: '2026-01-15T10:30:00+00:00',
    schema_version: 1,
  },
]

type LibraryStore = Parameters<typeof LibraryPanel>[0]['store']

function libraryStore(overrides: Partial<LibraryStore> = {}): LibraryStore {
  return {
    items: SAVED,
    loading: false,
    error: null,
    query: '',
    setQuery: vi.fn(),
    refresh: vi.fn(),
    save: vi.fn(async () => ({ ...SAVED[0]!, payload: {}, warning: '' })),
    open: vi.fn(async () => ({ ...SAVED[0]!, payload: {}, warning: '' })),
    duplicate: vi.fn(async () => ({ ...SAVED[0]!, id: 'inv-2', payload: {}, warning: '' })),
    remove: vi.fn(async () => true),
    currentId: null,
    setCurrentId: vi.fn(),
    ...overrides,
  } as LibraryStore
}

describe('Library', () => {
  const props = {
    canSave: true,
    buildPayload: () => ({ analysis: FIXTURE_ANALYSIS }),
    defaultTitle: 'Untitled',
    onOpen: vi.fn(),
  }

  it('lists saved investigations', () => {
    mockFetch({})
    wrap(<LibraryPanel store={libraryStore()} {...props} />)
    expect(screen.getByText('PowerShell staging')).toBeInTheDocument()
  })

  it('saves the current investigation', async () => {
    mockFetch({})
    const store = libraryStore()
    const user = userEvent.setup()
    wrap(<LibraryPanel store={store} {...props} />)

    await user.type(screen.getByLabelText(/^title$/i), 'My case')
    await user.click(screen.getByRole('button', { name: /save investigation/i }))

    await waitFor(() => expect(store.save).toHaveBeenCalled())
    expect(store.save).toHaveBeenCalledWith('My case', '', expect.any(Object))
  })

  it('updates in place when an investigation is already open', () => {
    mockFetch({})
    wrap(<LibraryPanel store={libraryStore({ currentId: 'inv-1' })} {...props} />)
    // The button reflects that a second save will not create a duplicate.
    expect(screen.getByRole('button', { name: /update investigation/i })).toBeInTheDocument()
    expect(screen.getByText(/Editing a saved record/i)).toBeInTheDocument()
  })

  it('opens a saved investigation', async () => {
    mockFetch({})
    const store = libraryStore()
    const onOpen = vi.fn()
    const user = userEvent.setup()
    wrap(<LibraryPanel store={store} {...props} onOpen={onOpen} />)

    await user.click(screen.getByRole('button', { name: /^open$/i }))
    await waitFor(() => expect(onOpen).toHaveBeenCalled())
  })

  it('duplicates an investigation', async () => {
    mockFetch({})
    const store = libraryStore()
    const user = userEvent.setup()
    wrap(<LibraryPanel store={store} {...props} />)

    await user.click(screen.getByRole('button', { name: /duplicate PowerShell staging/i }))
    await waitFor(() => expect(store.duplicate).toHaveBeenCalledWith('inv-1'))
  })

  it('requires confirmation before deleting', async () => {
    mockFetch({})
    const store = libraryStore()
    const user = userEvent.setup()
    wrap(<LibraryPanel store={store} {...props} />)

    await user.click(screen.getByRole('button', { name: /delete PowerShell staging/i }))
    // Nothing is deleted until the confirmation is accepted.
    expect(store.remove).not.toHaveBeenCalled()
    expect(screen.getByText(/permanently\?/i)).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: /^delete$/i }))
    await waitFor(() => expect(store.remove).toHaveBeenCalledWith('inv-1'))
  })

  it('can cancel a delete', async () => {
    mockFetch({})
    const store = libraryStore()
    const user = userEvent.setup()
    wrap(<LibraryPanel store={store} {...props} />)

    await user.click(screen.getByRole('button', { name: /delete PowerShell staging/i }))
    await user.click(screen.getByRole('button', { name: /cancel/i }))

    expect(store.remove).not.toHaveBeenCalled()
    expect(screen.queryByText(/permanently\?/i)).not.toBeInTheDocument()
  })

  it('shows an empty state when nothing is saved', () => {
    mockFetch({})
    wrap(<LibraryPanel store={libraryStore({ items: [] })} {...props} />)
    expect(screen.getByText(/No saved investigations yet/i)).toBeInTheDocument()
  })

  it('blocks saving before an analysis exists', () => {
    mockFetch({})
    wrap(<LibraryPanel store={libraryStore()} {...props} canSave={false} />)
    expect(screen.getByText(/nothing to save yet/i)).toBeInTheDocument()
  })
})
