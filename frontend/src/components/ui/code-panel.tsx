/**
 * Code panel for SPL and JSON.
 *
 * Preserves indentation, wraps long lines so a wide query cannot create
 * page-level horizontal overflow, caps its own height, and gives copy and
 * download explicit success/failure feedback.
 *
 * Highlighting is presentational only — see lib/highlight.ts. Colouring a rule
 * implies nothing about whether it parses or runs.
 */

import { useMemo, useState } from 'react'
import { Check, Copy, Download, X } from 'lucide-react'
import { Button } from './button'
import { EmptyState, Tooltip } from './primitives'
import { TOKEN_CLASS, tokenizeJSON, tokenizeSPL } from '@/lib/highlight'
import { cn, copyText, downloadText } from '@/lib/utils'

type CopyState = 'idle' | 'copied' | 'failed'

export function CodePanel({
  code,
  filename,
  maxHeight = 320,
  label,
  language = 'spl',
  className,
  emptyMessage = 'No query was generated for this rule.',
  onCopied,
}: {
  code: string
  /** When set, a download button is offered. */
  filename?: string
  maxHeight?: number
  label?: string
  /** 'yaml' renders plain (no highlighting) for Sigma rules. */
  language?: 'spl' | 'json' | 'yaml'
  className?: string
  emptyMessage?: string
  onCopied?: (ok: boolean) => void
}) {
  const [copyState, setCopyState] = useState<CopyState>('idle')
  const text = (code ?? '').trim()

  const tokens = useMemo(
    () =>
      language === 'json'
        ? tokenizeJSON(text)
        : language === 'yaml'
          ? [{ kind: 'plain' as const, text }]
          : tokenizeSPL(text),
    [text, language],
  )

  if (!text) {
    return <EmptyState message={emptyMessage} />
  }

  async function handleCopy() {
    const ok = await copyText(text)
    setCopyState(ok ? 'copied' : 'failed')
    onCopied?.(ok)
    window.setTimeout(() => setCopyState('idle'), 1800)
  }

  return (
    <div
      className={cn(
        'overflow-hidden rounded-xl border border-line bg-canvas',
        'transition-colors duration-[var(--dur-base)]',
        className,
      )}
    >
      <div className="flex items-center justify-between gap-2 border-b border-line bg-raised px-3 py-1.5">
        <span className="truncate font-mono text-[0.66rem] tracking-[0.1em] text-ink-faint uppercase">
          {label ?? (language === 'json' ? 'JSON' : language === 'yaml' ? 'Sigma YAML' : 'Splunk SPL')}
        </span>
        <div className="flex shrink-0 items-center gap-0.5">
          <Tooltip label={copyState === 'copied' ? 'Copied' : 'Copy to clipboard'}>
            <Button
              variant="ghost"
              size="icon"
              onClick={handleCopy}
              aria-label="Copy to clipboard"
              className={cn(
                copyState === 'copied' && 'text-ok',
                copyState === 'failed' && 'text-bad',
              )}
            >
              {/* Icon swap gives the action a definite, readable outcome. */}
              {copyState === 'copied' ? <Check /> : copyState === 'failed' ? <X /> : <Copy />}
            </Button>
          </Tooltip>
          {filename ? (
            <Tooltip label="Download">
              <Button
                variant="ghost"
                size="icon"
                onClick={() => downloadText(filename, `${text}\n`)}
                aria-label="Download"
              >
                <Download />
              </Button>
            </Tooltip>
          ) : null}
        </div>
      </div>

      <div className="overflow-y-auto" style={{ maxHeight }}>
        <pre
          className="px-3.5 py-3 font-mono text-[0.79rem] leading-[1.7]"
          style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}
        >
          <code>
            {tokens.map((token, index) => (
              <span key={index} className={TOKEN_CLASS[token.kind]}>
                {token.text}
              </span>
            ))}
          </code>
        </pre>
      </div>
    </div>
  )
}
