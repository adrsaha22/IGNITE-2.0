import { type ClassValue, clsx } from 'clsx'
import { twMerge } from 'tailwind-merge'

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

/**
 * Convert a score to a 0-100 bar percentage against its own scale.
 *
 * Out-of-range values are clamped at the boundary so a bar never overflows its
 * track. Callers display the raw value alongside its real maximum, so a score
 * of 105/125 is shown honestly rather than as "105/100".
 */
export function scorePercent(value: number | null | undefined, max: number): number {
  if (value == null || !Number.isFinite(value) || max <= 0) return 0
  return Math.max(0, Math.min(100, (value / max) * 100))
}

/** Whether a score falls outside its declared scale and should be reported. */
export function isScoreOutOfRange(value: number | null | undefined, max: number): boolean {
  if (value == null || !Number.isFinite(value)) return false
  return value < 0 || value > max
}

/** Semantic tone for a score, as a fraction of its own maximum. */
export type Tone = 'ok' | 'warn' | 'bad' | 'neutral'

export function scoreTone(value: number | null | undefined, max: number): Tone {
  if (value == null || !Number.isFinite(value)) return 'neutral'
  const pct = (value / max) * 100
  if (pct >= 75) return 'ok'
  if (pct >= 50) return 'warn'
  return 'bad'
}

/** Format an ISO timestamp for display, falling back to the raw string. */
export function formatTimestamp(iso: string): string {
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return iso
  return date.toLocaleString(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short',
  })
}

/** Copy text to the clipboard, reporting whether it succeeded. */
export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text)
    return true
  } catch {
    return false
  }
}

/** Trigger a browser download of text content. */
export function downloadText(filename: string, content: string, mime = 'text/plain') {
  const blob = new Blob([content], { type: mime })
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = filename
  document.body.appendChild(anchor)
  anchor.click()
  document.body.removeChild(anchor)
  URL.revokeObjectURL(url)
}

/** Filename-safe stamp derived from an ISO timestamp. */
export function fileStamp(iso: string): string {
  return iso.replace(/[:\-]/g, '').replace(/\..*$/, '')
}
