import { useCallback, useEffect, useRef, useState } from 'react'
import { AnimatePresence, motion } from 'motion/react'
import { CircleAlert, CornerDownLeft, Loader2, Sparkles, Terminal, X } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/primitives'
import { useReducedMotion } from '@/lib/motion'
import { cn } from '@/lib/utils'

export interface Example {
  label: string
  hint: string
  text: string
}

export const EXAMPLES: Example[] = [
  {
    label: 'PowerShell staging',
    hint: 'Download cradle into scheduled-task persistence',
    text: 'Attacker used PowerShell to download a payload from GitHub via DownloadString and created a scheduled task with schtasks for persistence',
  },
  {
    label: 'LOLBin transfer',
    hint: 'certutil used to pull and decode a payload',
    text: 'Threat actor used certutil.exe to download an encoded payload from a remote host and decoded it on disk',
  },
  {
    label: 'Credential access',
    hint: 'Memory dumping against a domain controller',
    text: 'Adversary ran mimikatz against lsass to perform credential dumping on a domain controller',
  },
]

/** Rotating hints, shown only while the field is empty and unfocused. */
const PLACEHOLDERS = [
  'An adversary used rundll32 to execute a DLL export and established persistence via a registry run key…',
  'A threat actor staged data with 7-Zip before exfiltrating it over HTTPS to an external host…',
  'Suspicious wmic process call create spawning from an Office application…',
  'PowerShell with an encoded command pulling a second stage into memory…',
]

const MAX_CHARS = 8000
const MIN_USEFUL_CHARS = 12
const ROTATE_MS = 5200

export function AttackInput({
  value,
  onChange,
  onGenerate,
  loading,
  error,
  onDismissError,
}: {
  value: string
  onChange: (value: string) => void
  onGenerate: () => void
  loading: boolean
  error: string | null
  onDismissError: () => void
}) {
  const reduced = useReducedMotion()
  const trimmed = value.trim()
  const empty = trimmed.length === 0
  // Guidance only — the button stays enabled so the backend remains the
  // authority on what it will accept.
  const tooShort = !empty && trimmed.length < MIN_USEFUL_CHARS

  const [focused, setFocused] = useState(false)
  const [placeholderIndex, setPlaceholderIndex] = useState(0)
  const shellRef = useRef<HTMLDivElement>(null)

  // Rotation stops for good once the user focuses or types, so it never
  // competes with reading or editing.
  const rotating = empty && !focused && !reduced
  useEffect(() => {
    if (!rotating) return
    const timer = window.setInterval(() => {
      setPlaceholderIndex((index) => (index + 1) % PLACEHOLDERS.length)
    }, ROTATE_MS)
    return () => window.clearInterval(timer)
  }, [rotating])

  /**
   * Cursor-following highlight, confined to this panel. Writes CSS variables
   * directly rather than setting React state, so pointer movement never
   * triggers a re-render or interferes with typing.
   */
  const handlePointerMove = useCallback((event: React.PointerEvent<HTMLDivElement>) => {
    const shell = shellRef.current
    if (!shell) return
    const rect = shell.getBoundingClientRect()
    shell.style.setProperty('--mx', `${event.clientX - rect.left}px`)
    shell.style.setProperty('--my', `${event.clientY - rect.top}px`)
  }, [])

  function handleKeyDown(event: React.KeyboardEvent<HTMLTextAreaElement>) {
    if ((event.metaKey || event.ctrlKey) && event.key === 'Enter' && !empty && !loading) {
      event.preventDefault()
      onGenerate()
    }
  }

  return (
    <div
      ref={shellRef}
      onPointerMove={handlePointerMove}
      onPointerEnter={(event) => event.currentTarget.setAttribute('data-active', 'true')}
      onPointerLeave={(event) => event.currentTarget.setAttribute('data-active', 'false')}
      className={cn(
        'spotlight sheen relative overflow-hidden rounded-[var(--radius-panel)] border bg-surface',
        'transition-colors duration-[var(--dur-slow)] ease-[var(--ease-out-soft)]',
        focused ? 'border-primary-line' : 'border-line',
      )}
    >
      {/* Restrained violet wash + masked grid, composer only. */}
      <div className="pointer-events-none absolute inset-0 hero-glow" aria-hidden />
      <div className="pointer-events-none absolute inset-x-0 top-0 h-44 grid-faint" aria-hidden />

      <div className="relative p-5 sm:p-6">
        {/* Welcome composition appears only while the composer is empty. */}
        <AnimatePresence initial={false}>
          {empty && (
            <motion.div
              initial={reduced ? false : { opacity: 0, y: -6 }}
              animate={{ opacity: 1, y: 0 }}
              exit={reduced ? { opacity: 0 } : { opacity: 0, y: -6 }}
              transition={reduced ? { duration: 0 } : { duration: 0.28, ease: [0.22, 1, 0.36, 1] }}
              className="mb-5"
            >
              <h1 className="text-xl font-semibold tracking-tight text-ink sm:text-2xl">
                Describe the activity.{' '}
                <span className="text-gradient">Find the signal.</span>
              </h1>
              <p className="mt-1.5 max-w-xl text-sm leading-relaxed text-ink-muted">
                Turn an attack narrative into ranked Splunk detection candidates, mapped to
                ATT&amp;CK and checked before you take them anywhere near production.
              </p>
            </motion.div>
          )}
        </AnimatePresence>

        <div className="mb-2.5 flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <Terminal
              className={cn(
                'size-4 transition-colors duration-[var(--dur-base)]',
                focused ? 'text-primary-bright' : 'text-ink-faint',
              )}
            />
            <h2 className="text-sm font-semibold tracking-tight text-ink">Attack scenario</h2>
          </div>
          <Badge tone={value.length > MAX_CHARS * 0.9 ? 'warn' : 'neutral'} mono>
            {value.length.toLocaleString()} / {MAX_CHARS.toLocaleString()}
          </Badge>
        </div>

        <label htmlFor="attack-scenario" className="sr-only">
          Attack scenario description
        </label>
        <div className="relative">
          <textarea
            id="attack-scenario"
            value={value}
            onChange={(event) => onChange(event.target.value)}
            onKeyDown={handleKeyDown}
            onFocus={() => setFocused(true)}
            onBlur={() => setFocused(false)}
            maxLength={MAX_CHARS}
            rows={5}
            spellCheck={false}
            aria-describedby="attack-hint"
            className={cn(
              'w-full resize-y rounded-xl border bg-canvas px-4 py-3.5',
              'font-mono text-[0.85rem] leading-relaxed text-ink caret-primary-bright',
              'transition-[border-color,box-shadow] duration-[var(--dur-base)] ease-[var(--ease-out-soft)]',
              'focus:outline-none',
              focused
                ? 'border-primary-line shadow-[0_0_0_3px_var(--c-primary-soft)]'
                : 'border-line',
            )}
          />

          {empty && (
            <div
              aria-hidden
              className="pointer-events-none absolute inset-x-4 top-3.5 font-mono text-[0.85rem] leading-relaxed text-ink-faint"
            >
              {/* Fixed height prevents layout shift as hints rotate. */}
              <AnimatePresence mode="wait" initial={false}>
                <motion.span
                  key={focused ? 'static' : placeholderIndex}
                  initial={reduced ? false : { opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={reduced ? { opacity: 0 } : { opacity: 0 }}
                  transition={reduced ? { duration: 0 } : { duration: 0.35 }}
                  className="block"
                >
                  {focused ? PLACEHOLDERS[0] : PLACEHOLDERS[placeholderIndex]}
                </motion.span>
              </AnimatePresence>
            </div>
          )}
        </div>

        {/* Example scenarios: descriptive cards when empty, compact chips once
            the user has written something. */}
        {empty ? (
          <div className="mt-4 grid gap-2 sm:grid-cols-3">
            {EXAMPLES.map((example, index) => (
              <motion.button
                key={example.label}
                type="button"
                onClick={() => onChange(example.text)}
                initial={reduced ? false : { opacity: 0, y: 6 }}
                animate={{ opacity: 1, y: 0 }}
                transition={
                  reduced
                    ? { duration: 0 }
                    : { duration: 0.28, delay: 0.04 * index, ease: [0.22, 1, 0.36, 1] }
                }
                className={cn(
                  'group rounded-xl border border-line bg-raised p-3 text-left',
                  'transition-[border-color,background-color] duration-[var(--dur-fast)]',
                  'hover:border-primary-line hover:bg-primary-soft',
                )}
              >
                <span className="block text-xs font-semibold text-ink group-hover:text-primary-bright">
                  {example.label}
                </span>
                <span className="mt-1 block text-[0.7rem] leading-relaxed text-ink-faint">
                  {example.hint}
                </span>
              </motion.button>
            ))}
          </div>
        ) : (
          <div className="mt-3 flex flex-wrap items-center gap-1.5">
            <span className="mr-1 text-[0.68rem] font-semibold tracking-[0.09em] text-ink-faint uppercase">
              Examples
            </span>
            {EXAMPLES.map((example) => (
              <button
                key={example.label}
                type="button"
                onClick={() => onChange(example.text)}
                className={cn(
                  'rounded-full border border-line bg-raised px-2.5 py-1 text-xs text-ink-muted',
                  'transition-[color,border-color,transform] duration-[var(--dur-fast)] ease-[var(--ease-out-soft)]',
                  'hover:border-primary-line hover:text-primary-bright active:scale-[0.97]',
                )}
              >
                {example.label}
              </button>
            ))}
            <button
              type="button"
              onClick={() => onChange('')}
              className="ml-auto flex items-center gap-1 rounded-full px-2 py-1 text-xs text-ink-faint transition-colors hover:text-ink"
            >
              <X className="size-3" />
              Clear
            </button>
          </div>
        )}

        <div className="mt-4 flex flex-wrap items-center justify-between gap-3 border-t border-line pt-4">
          <p id="attack-hint" className="text-xs text-ink-faint">
            {empty ? (
              'Pick an example above, or describe what you observed.'
            ) : tooShort ? (
              <span className="text-warn">
                Add a little more detail — tools, commands or behaviour.
              </span>
            ) : (
              <span className="inline-flex items-center gap-1.5">
                <kbd className="rounded border border-line-strong bg-raised px-1 font-mono text-[0.68rem]">
                  Ctrl
                </kbd>
                <span>+</span>
                <kbd className="inline-flex items-center gap-0.5 rounded border border-line-strong bg-raised px-1 font-mono text-[0.68rem]">
                  <CornerDownLeft className="size-2.5" />
                  Enter
                </kbd>
                <span>to generate</span>
              </span>
            )}
          </p>

          <Button variant="primary" size="lg" onClick={onGenerate} disabled={empty || loading}>
            {loading ? (
              <>
                <Loader2 className="animate-spin" />
                Analysing…
              </>
            ) : (
              <>
                <Sparkles />
                Generate detection rules
              </>
            )}
          </Button>
        </div>

        <AnimatePresence>
          {error && (
            <motion.div
              initial={reduced ? false : { opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={reduced ? { opacity: 0 } : { opacity: 0, height: 0 }}
              transition={reduced ? { duration: 0 } : { duration: 0.24, ease: [0.22, 1, 0.36, 1] }}
              className="overflow-hidden"
            >
              <div className="mt-4 flex items-start gap-2.5 rounded-xl border border-bad/30 bg-bad-soft px-3.5 py-3">
                <CircleAlert className="mt-0.5 size-4 shrink-0 text-bad" />
                <div className="min-w-0 flex-1">
                  <p className="text-xs leading-relaxed text-bad">{error}</p>
                  <button
                    onClick={onGenerate}
                    className="mt-1.5 text-xs font-medium text-primary-bright underline-offset-2 hover:underline"
                  >
                    Try again
                  </button>
                </div>
                <Button
                  variant="ghost"
                  size="icon"
                  onClick={onDismissError}
                  aria-label="Dismiss error"
                >
                  <X />
                </Button>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </div>
  )
}
