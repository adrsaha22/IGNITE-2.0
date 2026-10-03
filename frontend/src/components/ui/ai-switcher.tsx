/**
 * Choose which AI generates rules and powers the Assistant.
 *
 * Only providers whose key is in the backend .env can be chosen; keys are
 * never entered or shown here. "Demo (no AI)" is always available.
 */

import { useEffect, useRef, useState } from 'react'
import { Bot, Check, ChevronDown, FlaskConical, HardDrive, Loader2, RotateCcw } from 'lucide-react'
import { Button } from './button'
import { useToast } from './toast'
import type { AIProvidersState } from '@/hooks/useAIProviders'
import type { AIChoice, AIProviderOption } from '@/types/api'
import { cn } from '@/lib/utils'

function statusDot(option: AIProviderOption) {
  if (option.id === 'demo') return 'bg-warn'
  if (!option.configured) return 'bg-ink-faint'
  return option.ready ? 'bg-ok' : 'bg-warn'
}

/** The list of choices, used in the header menu and on the Platform page. */
export function AIProviderList({
  state,
  onChosen,
}: {
  state: AIProvidersState
  onChosen?: () => void
}) {
  const toast = useToast()
  const { data, busy } = state
  const [pending, setPending] = useState<AIChoice | null>(null)

  if (!data) {
    return <p className="px-3 py-2 text-xs text-ink-faint">{state.error ?? 'Loading…'}</p>
  }

  async function pick(option: AIProviderOption) {
    if (option.id === data?.active || !option.configured) return
    setPending(option.id)
    try {
      await state.choose(option.id)
      toast(
        option.id === 'demo' ? 'AI switched off — Demo mode' : `Now using ${option.label}`,
        'success',
      )
      onChosen?.()
    } catch (err) {
      toast((err as Error).message, 'error')
    } finally {
      setPending(null)
    }
  }

  async function handleReset() {
    try {
      await state.reset()
      toast('Back to the provider set in .env', 'success')
      onChosen?.()
    } catch (err) {
      toast((err as Error).message, 'error')
    }
  }

  return (
    <div>
      <ul role="radiogroup" aria-label="AI provider" className="space-y-1">
        {data.options.map((option) => {
          const active = option.id === data.active
          const disabled = !option.configured || busy
          return (
            <li key={option.id}>
              <button
                role="radio"
                aria-checked={active}
                disabled={disabled}
                onClick={() => void pick(option)}
                className={cn(
                  'flex w-full items-start gap-2.5 rounded-lg border px-2.5 py-2 text-left transition-colors',
                  active
                    ? 'border-primary-line bg-primary-soft'
                    : 'border-transparent hover:bg-raised',
                  !option.configured && 'cursor-not-allowed opacity-60 hover:bg-transparent',
                )}
              >
                <span className={cn('mt-1.5 size-2 shrink-0 rounded-full', statusDot(option))} />
                <span className="min-w-0 flex-1">
                  <span className="flex items-center gap-1.5 text-sm text-ink">
                    {option.label}
                    {option.id === 'demo' ? (
                      <FlaskConical className="size-3 text-warn" aria-hidden />
                    ) : option.local ? (
                      <HardDrive className="size-3 text-ink-faint" aria-label="runs locally" />
                    ) : null}
                  </span>
                  <span className="block truncate font-mono text-[0.68rem] text-ink-faint">
                    {option.model}
                  </span>
                  {option.message && (
                    <span
                      className={cn(
                        'mt-0.5 block text-[0.7rem] leading-snug',
                        option.configured && option.ready ? 'text-ink-muted' : 'text-warn',
                      )}
                    >
                      {option.message}
                    </span>
                  )}
                </span>
                {pending === option.id ? (
                  <Loader2 className="mt-0.5 size-3.5 shrink-0 animate-spin text-primary-bright" />
                ) : active ? (
                  <Check className="mt-0.5 size-3.5 shrink-0 text-primary-bright" />
                ) : null}
              </button>
            </li>
          )
        })}
      </ul>
      <div className="mt-2 flex items-center justify-between gap-2 border-t border-line px-1 pt-2">
        <p className="text-[0.68rem] leading-snug text-ink-faint">
          API keys are read from the backend <span className="font-mono">.env</span> only.
        </p>
        {data.overridden && (
          <Button variant="ghost" size="sm" onClick={() => void handleReset()} disabled={busy}>
            <RotateCcw />
            Use .env default
          </Button>
        )}
      </div>
    </div>
  )
}

/** Compact header control: the active AI, opening the list of choices. */
export function AISwitcher({ state }: { state: AIProvidersState }) {
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)
  const active = state.data?.options.find((o) => o.id === state.data?.active)

  useEffect(() => {
    if (!open) return
    const onDown = (event: MouseEvent) => {
      if (!ref.current?.contains(event.target as Node)) setOpen(false)
    }
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setOpen(false)
    }
    document.addEventListener('mousedown', onDown)
    window.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onDown)
      window.removeEventListener('keydown', onKey)
    }
  }, [open])

  return (
    <div ref={ref} className="relative">
      <button
        onClick={() => {
          setOpen((value) => !value)
          if (!open) void state.refresh()
        }}
        aria-haspopup="true"
        aria-expanded={open}
        aria-label={`AI provider: ${active?.label ?? 'loading'}`}
        className="inline-flex items-center gap-1.5 rounded-full border border-line bg-raised px-2.5 py-1 text-[0.7rem] text-ink-muted transition-colors hover:border-primary-line hover:text-ink"
      >
        {active ? (
          <span className={cn('size-1.5 shrink-0 rounded-full', statusDot(active))} />
        ) : (
          <Bot className="size-3" />
        )}
        <span className="max-w-[9rem] truncate">
          {active ? (active.id === 'demo' ? 'Demo · no AI' : active.label) : 'AI'}
        </span>
        <ChevronDown className="size-3" aria-hidden />
      </button>
      {open && (
        <div className="absolute right-0 z-50 mt-2 w-80 max-w-[calc(100vw-2rem)] rounded-xl border border-line-strong bg-overlay p-2 shadow-[var(--e-overlay)]">
          <p className="px-1 pb-1.5 text-[0.66rem] font-semibold tracking-[0.09em] text-ink-faint uppercase">
            AI for generation and the Assistant
          </p>
          <AIProviderList state={state} onChosen={() => setOpen(false)} />
        </div>
      )}
    </div>
  )
}
