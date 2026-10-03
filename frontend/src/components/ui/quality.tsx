/**
 * Quality-check and governance display shared by generation and the library.
 *
 * Every number shown here was computed by the backend. A check that did not
 * run is shown as "skipped" with its reason — never as passed.
 */

import { CircleCheck, CircleDashed, CircleX, Rocket, TriangleAlert } from 'lucide-react'
import { Badge } from './primitives'
import type { CheckStatus, DeployMode, QualityCheck, RuleStatus } from '@/types/api'
import { cn } from '@/lib/utils'

const GRADE_TONE: Record<string, 'ok' | 'primary' | 'warn' | 'bad'> = {
  Ready: 'ok',
  Good: 'primary',
  'Needs work': 'warn',
  Poor: 'bad',
}

/** Quality score with its grade. */
export function GradeBadge({ score, grade }: { score: number; grade: string }) {
  return (
    <Badge tone={GRADE_TONE[grade] ?? 'neutral'} mono>
      {score}/100 · {grade}
    </Badge>
  )
}

const STATUS_ICON: Record<CheckStatus, { icon: typeof CircleCheck; className: string; label: string }> = {
  pass: { icon: CircleCheck, className: 'text-ok', label: 'Passed' },
  warn: { icon: TriangleAlert, className: 'text-warn', label: 'Warning' },
  fail: { icon: CircleX, className: 'text-bad', label: 'Failed' },
  skip: { icon: CircleDashed, className: 'text-ink-faint', label: 'Skipped' },
}

/** The weighted checks, failures first. */
export function ChecksList({ checks }: { checks: QualityCheck[] }) {
  const order: Record<CheckStatus, number> = { fail: 0, warn: 1, pass: 2, skip: 3 }
  const sorted = [...checks].sort((a, b) => order[a.status] - order[b.status])
  return (
    <ul className="divide-y divide-line" aria-label="Quality checks">
      {sorted.map((check) => {
        const { icon: Icon, className, label } = STATUS_ICON[check.status]
        return (
          <li key={check.name} className="flex items-start gap-2.5 py-2">
            <Icon className={cn('mt-0.5 size-3.5 shrink-0', className)} aria-label={label} />
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-baseline justify-between gap-x-2">
                <span className="text-xs font-medium text-ink">{check.name}</span>
                <span className="font-mono text-[0.65rem] text-ink-faint">
                  weight {check.weight}
                </span>
              </div>
              <p className="mt-0.5 text-[0.72rem] leading-relaxed break-words text-ink-muted">
                {check.detail}
              </p>
            </div>
          </li>
        )
      })}
    </ul>
  )
}

/** Count of checks by outcome, e.g. "11 passed · 2 warnings · 1 skipped". */
export function checkCounts(checks: QualityCheck[]) {
  const counts = { pass: 0, warn: 0, fail: 0, skip: 0 }
  checks.forEach((check) => {
    counts[check.status] += 1
  })
  return counts
}

const RULE_STATUS_TONE: Record<RuleStatus, 'neutral' | 'ok' | 'bad'> = {
  draft: 'neutral',
  approved: 'ok',
  rejected: 'bad',
}

export function RuleStatusBadge({ status }: { status: RuleStatus }) {
  return <Badge tone={RULE_STATUS_TONE[status]}>{status}</Badge>
}

export function DeploymentBadge({ mode, stale }: { mode: DeployMode | ''; stale?: boolean }) {
  if (!mode) return null
  return (
    <Badge tone={stale ? 'warn' : mode === 'live' ? 'accent' : 'primary'}>
      <Rocket className="size-3" />
      {mode}
      {stale ? ' · outdated' : ''}
    </Badge>
  )
}
