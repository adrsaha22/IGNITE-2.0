/** Theme selection, persistence and system-preference handling. */

import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ThemeProvider, useTheme } from '@/hooks/useTheme'
import { ThemeSwitcher } from '@/components/ui/theme-switcher'
import { TooltipProvider } from '@/components/ui/primitives'

/** Install a matchMedia stub reporting a given OS preference. */
function stubMatchMedia(prefersLight: boolean) {
  const listeners: ((e: MediaQueryListEvent) => void)[] = []
  vi.stubGlobal(
    'matchMedia',
    vi.fn((query: string) => ({
      matches: query.includes('light') ? prefersLight : !prefersLight,
      media: query,
      addEventListener: (_: string, fn: (e: MediaQueryListEvent) => void) => listeners.push(fn),
      removeEventListener: () => {},
      addListener: () => {},
      removeListener: () => {},
      dispatchEvent: () => true,
    })),
  )
  return listeners
}

function Probe() {
  const { preference, resolved } = useTheme()
  return <span data-testid="probe">{`${preference}:${resolved}`}</span>
}

function renderSwitcher() {
  return render(
    <ThemeProvider>
      <TooltipProvider>
        <ThemeSwitcher />
        <Probe />
      </TooltipProvider>
    </ThemeProvider>,
  )
}

beforeEach(() => {
  localStorage.clear()
  document.documentElement.removeAttribute('data-theme')
  vi.restoreAllMocks()
})

describe('theme preference', () => {
  it('defaults to system and follows a dark OS preference', () => {
    stubMatchMedia(false)
    renderSwitcher()
    expect(screen.getByTestId('probe')).toHaveTextContent('system:dark')
    expect(document.documentElement.dataset.theme).toBe('dark')
  })

  it('follows a light OS preference when set to system', () => {
    stubMatchMedia(true)
    renderSwitcher()
    expect(screen.getByTestId('probe')).toHaveTextContent('system:light')
    expect(document.documentElement.dataset.theme).toBe('light')
  })

  it('applies an explicit light choice over the OS preference', async () => {
    stubMatchMedia(false) // OS says dark
    const user = userEvent.setup()
    renderSwitcher()

    await user.click(screen.getByRole('radio', { name: /light theme/i }))
    expect(screen.getByTestId('probe')).toHaveTextContent('light:light')
    expect(document.documentElement.dataset.theme).toBe('light')
  })

  it('persists an explicit preference to localStorage', async () => {
    stubMatchMedia(false)
    const user = userEvent.setup()
    renderSwitcher()

    await user.click(screen.getByRole('radio', { name: /light theme/i }))
    expect(localStorage.getItem('ignite.theme')).toBe('light')
  })

  it('restores a persisted preference on mount', () => {
    localStorage.setItem('ignite.theme', 'light')
    stubMatchMedia(false) // OS says dark; the stored choice must win
    renderSwitcher()

    expect(screen.getByTestId('probe')).toHaveTextContent('light:light')
  })

  it('clears the stored key when returning to system', async () => {
    localStorage.setItem('ignite.theme', 'light')
    stubMatchMedia(false)
    const user = userEvent.setup()
    renderSwitcher()

    await user.click(screen.getByRole('radio', { name: /system theme/i }))
    expect(localStorage.getItem('ignite.theme')).toBeNull()
    expect(screen.getByTestId('probe')).toHaveTextContent('system:dark')
  })

  it('marks the active option with aria-checked', async () => {
    stubMatchMedia(false)
    const user = userEvent.setup()
    renderSwitcher()

    await user.click(screen.getByRole('radio', { name: /dark theme/i }))
    expect(screen.getByRole('radio', { name: /dark theme/i })).toHaveAttribute(
      'aria-checked',
      'true',
    )
    expect(screen.getByRole('radio', { name: /light theme/i })).toHaveAttribute(
      'aria-checked',
      'false',
    )
  })

  it('survives localStorage being unavailable', async () => {
    stubMatchMedia(false)
    const original = Storage.prototype.setItem
    Storage.prototype.setItem = () => {
      throw new Error('storage blocked')
    }

    const user = userEvent.setup()
    renderSwitcher()
    await user.click(screen.getByRole('radio', { name: /light theme/i }))

    // The in-memory preference still applies even though persistence failed.
    expect(screen.getByTestId('probe')).toHaveTextContent('light:light')
    Storage.prototype.setItem = original
  })

  it('ignores a corrupted stored value', () => {
    localStorage.setItem('ignite.theme', 'chartreuse')
    stubMatchMedia(false)
    renderSwitcher()

    expect(screen.getByTestId('probe')).toHaveTextContent('system:dark')
  })
})
