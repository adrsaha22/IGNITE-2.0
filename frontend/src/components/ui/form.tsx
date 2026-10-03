/** Labelled form controls, styled to match the existing editor inputs. */

import * as React from 'react'
import { cn } from '@/lib/utils'

const CONTROL =
  'w-full rounded-lg border border-line bg-canvas px-3 py-2 text-sm text-ink placeholder:text-ink-faint focus:border-primary-line focus:outline-none disabled:opacity-50'

export function Field({
  id,
  label,
  hint,
  children,
  className,
}: {
  id: string
  label: string
  hint?: React.ReactNode
  children: React.ReactNode
  className?: string
}) {
  return (
    <div className={className}>
      <label
        htmlFor={id}
        className="mb-1 block text-[0.68rem] font-semibold tracking-[0.09em] text-ink-faint uppercase"
      >
        {label}
      </label>
      {children}
      {hint ? <p className="mt-1 text-[0.7rem] leading-relaxed text-ink-faint">{hint}</p> : null}
    </div>
  )
}

export const TextInput = React.forwardRef<HTMLInputElement, React.InputHTMLAttributes<HTMLInputElement>>(
  ({ className, ...props }, ref) => <input ref={ref} className={cn(CONTROL, className)} {...props} />,
)
TextInput.displayName = 'TextInput'

export const TextArea = React.forwardRef<
  HTMLTextAreaElement,
  React.TextareaHTMLAttributes<HTMLTextAreaElement> & { mono?: boolean }
>(({ className, mono, ...props }, ref) => (
  <textarea
    ref={ref}
    className={cn(CONTROL, 'resize-y', mono && 'font-mono text-[0.78rem] leading-relaxed', className)}
    {...props}
  />
))
TextArea.displayName = 'TextArea'

export const Select = React.forwardRef<HTMLSelectElement, React.SelectHTMLAttributes<HTMLSelectElement>>(
  ({ className, ...props }, ref) => <select ref={ref} className={cn(CONTROL, className)} {...props} />,
)
Select.displayName = 'Select'

/** Split a textarea into non-empty trimmed lines. */
export function lines(value: string): string[] {
  return value
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
}
