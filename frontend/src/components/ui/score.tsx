/**
 * Score display.
 *
 * A score is always shown against its own declared maximum, so a candidate
 * score of 105/125 never renders as "105/100". Values outside their scale are
 * clamped for the bar and flagged, never silently drawn.
 *
 * Bars animate once on appearance. They are heuristics, never probabilities —
 * callers pass a caveat saying what the number actually is.
 */

import { AlertTriangle } from 'lucide-react'
import { motion } from 'motion/react'
import { useReducedMotion } from '@/lib/motion'
import { cn, isScoreOutOfRange, scorePercent, scoreTone } from '@/lib/utils'

const TONE_BAR: Record<string, string> = {
  ok: 'bg-ok',
  warn: 'bg-warn',
  bad: 'bg-bad',
  neutral: 'bg-ink-faint',
}

const TONE_TEXT: Record<string, string> = {
  ok: 'text-ok',
  warn: 'text-warn',
  bad: 'text-bad',
  neutral: 'text-ink-muted',
}

export function ScoreMeter({
  label,
  value,
  max,
  caveat,
  size = 'md',
  className,
}: {
  label: string
  value: number | null
  max: number
  /** Short note on what the number is, e.g. "static checks". */
  caveat?: string
  size?: 'sm' | 'md'
  className?: string
}) {
  const reduced = useReducedMotion()
  const tone = scoreTone(value, max)
  const pct = scorePercent(value, max)
  const outOfRange = isScoreOutOfRange(value, max)
  // A null score means the check did not run. Rendering 0 would read as
  // "scored badly" rather than "not scored".
  const notScored = value === null || value === undefined

  return (
    <div className={cn('min-w-0', className)}>
      <div className="flex items-baseline justify-between gap-2">
        <span className="truncate text-[0.68rem] font-semibold tracking-[0.09em] text-ink-faint uppercase">
          {label}
        </span>
        {outOfRange ? (
          <span title={`Reported value is outside the 0-${max} scale`}>
            <AlertTriangle className="size-3 text-warn" aria-hidden />
          </span>
        ) : null}
      </div>

      <div className="mt-1.5 flex items-baseline gap-1">
        <span
          className={cn(
            'font-semibold tabular-nums',
            size === 'md' ? 'text-[1.7rem] leading-none' : 'text-lg leading-none',
            notScored ? 'text-ink-faint' : TONE_TEXT[tone],
          )}
        >
          {notScored ? '—' : value}
        </span>
        {!notScored && <span className="text-xs text-ink-faint">/ {max}</span>}
      </div>

      <div
        className="mt-2 h-1 w-full overflow-hidden rounded-full bg-line"
        role="meter"
        aria-valuenow={value ?? 0}
        aria-valuemin={0}
        aria-valuemax={max}
        aria-label={label}
      >
        <motion.div
          className={cn('h-full rounded-full', TONE_BAR[tone])}
          initial={reduced ? false : { width: 0 }}
          animate={{ width: `${pct}%` }}
          transition={reduced ? { duration: 0 } : { duration: 0.7, ease: [0.22, 1, 0.36, 1] }}
        />
      </div>

      {notScored ? (
        <p className="mt-1.5 text-[0.68rem] text-ink-faint">Not scored on this path</p>
      ) : caveat ? (
        <p className="mt-1.5 text-[0.68rem] text-ink-faint">{caveat}</p>
      ) : null}
    </div>
  )
}

/** A compact labelled statistic with no implied scale. */
export function Stat({
  label,
  value,
  note,
  tone = 'neutral',
}: {
  label: string
  value: React.ReactNode
  note?: string
  tone?: 'neutral' | 'primary' | 'accent'
}) {
  return (
    <div className="min-w-0">
      <div className="text-[0.68rem] font-semibold tracking-[0.09em] text-ink-faint uppercase">
        {label}
      </div>
      <div
        className={cn(
          'mt-1.5 text-[1.7rem] leading-none font-semibold tabular-nums',
          tone === 'primary' && 'text-primary-bright',
          tone === 'accent' && 'text-accent',
          tone === 'neutral' && 'text-ink',
        )}
      >
        {value}
      </div>
      {note ? <p className="mt-1.5 text-[0.68rem] text-ink-faint">{note}</p> : null}
    </div>
  )
}
