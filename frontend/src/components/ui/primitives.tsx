/** Shared primitives: panels, badges, tabs, tooltips, disclosures, empty states. */

import * as React from 'react'
import * as TabsPrimitive from '@radix-ui/react-tabs'
import * as TooltipPrimitive from '@radix-ui/react-tooltip'
import { ChevronRight } from 'lucide-react'
import { cva, type VariantProps } from 'class-variance-authority'
import { cn } from '@/lib/utils'

/* ------------------------------------------------------------------ Panel */

export function Panel({
  className,
  interactive = false,
  children,
  ...props
}: React.HTMLAttributes<HTMLDivElement> & { interactive?: boolean }) {
  return (
    <div
      className={cn(
        'sheen rounded-[var(--radius-panel)] border border-line bg-surface',
        interactive &&
          'transition-colors duration-[var(--dur-base)] ease-[var(--ease-out-soft)] hover:border-line-strong',
        className,
      )}
      {...props}
    >
      {children}
    </div>
  )
}

export function PanelHeader({
  title,
  description,
  icon,
  actions,
  className,
}: {
  title: React.ReactNode
  description?: React.ReactNode
  icon?: React.ReactNode
  actions?: React.ReactNode
  className?: string
}) {
  return (
    <div
      className={cn(
        'flex flex-wrap items-start justify-between gap-3 border-b border-line px-4 py-3',
        className,
      )}
    >
      <div className="flex min-w-0 items-start gap-2.5">
        {icon ? <span className="mt-0.5 shrink-0 text-primary-bright">{icon}</span> : null}
        <div className="min-w-0">
          <h2 className="text-sm font-semibold tracking-tight text-ink">{title}</h2>
          {description ? (
            <p className="mt-0.5 text-xs leading-relaxed text-ink-muted">{description}</p>
          ) : null}
        </div>
      </div>
      {/* min-w-0 lets long action groups wrap instead of forcing overflow. */}
      {actions ? <div className="flex min-w-0 flex-wrap items-center gap-2">{actions}</div> : null}
    </div>
  )
}

/* ------------------------------------------------------------------ Badge */

const badgeVariants = cva(
  'inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-xs font-medium',
  {
    variants: {
      tone: {
        primary: 'border-primary-line bg-primary-soft text-primary-bright',
        accent: 'border-accent-line bg-accent-soft text-accent',
        neutral: 'border-line-strong bg-raised text-ink-muted',
        ok: 'border-ok/30 bg-ok-soft text-ok',
        warn: 'border-warn/30 bg-warn-soft text-warn',
        bad: 'border-bad/30 bg-bad-soft text-bad',
      },
      mono: { true: 'font-mono tabular-nums', false: '' },
    },
    defaultVariants: { tone: 'neutral', mono: false },
  },
)

export interface BadgeProps
  extends React.HTMLAttributes<HTMLSpanElement>,
    VariantProps<typeof badgeVariants> {}

export function Badge({ className, tone, mono, ...props }: BadgeProps) {
  return <span className={cn(badgeVariants({ tone, mono }), className)} {...props} />
}

/* ------------------------------------------------------------ Empty state */

export function EmptyState({
  icon,
  message,
  className,
}: {
  icon?: React.ReactNode
  message: string
  className?: string
}) {
  return (
    <div
      className={cn(
        'flex items-center gap-2 rounded-lg border border-dashed border-line px-3 py-2.5 text-xs text-ink-faint',
        className,
      )}
    >
      {icon}
      <span>{message}</span>
    </div>
  )
}

/* ----------------------------------------------------------- Section label */

export function SectionLabel({
  children,
  className,
}: {
  children: React.ReactNode
  className?: string
}) {
  return (
    <h3
      className={cn(
        'mb-2 text-[0.68rem] font-semibold tracking-[0.09em] text-ink-faint uppercase',
        className,
      )}
    >
      {children}
    </h3>
  )
}

/* ------------------------------------------------------------------- Tabs */

export const Tabs = TabsPrimitive.Root

export function TabsList({
  className,
  ...props
}: React.ComponentPropsWithoutRef<typeof TabsPrimitive.List>) {
  return (
    <TabsPrimitive.List
      className={cn(
        'relative flex gap-0.5 overflow-x-auto border-b border-line',
        '[-ms-overflow-style:none] [scrollbar-width:none] [&::-webkit-scrollbar]:hidden',
        className,
      )}
      {...props}
    />
  )
}

/**
 * Tab trigger with an underline indicator.
 *
 * The indicator belongs to each trigger and scales in when active, giving the
 * slide impression without measuring DOM positions on every render.
 */
export function TabsTrigger({
  className,
  children,
  ...props
}: React.ComponentPropsWithoutRef<typeof TabsPrimitive.Trigger>) {
  return (
    <TabsPrimitive.Trigger
      className={cn(
        'group relative shrink-0 px-3.5 py-2.5 text-sm font-medium text-ink-muted',
        'transition-colors duration-[var(--dur-base)] ease-[var(--ease-out-soft)]',
        'hover:text-ink data-[state=active]:text-primary-bright',
        className,
      )}
      {...props}
    >
      {children}
      <span
        aria-hidden
        className={cn(
          'absolute inset-x-2 -bottom-px h-0.5 origin-center rounded-full bg-primary-bright',
          'scale-x-0 opacity-0 transition-all duration-[var(--dur-base)] ease-[var(--ease-out-soft)]',
          'group-data-[state=active]:scale-x-100 group-data-[state=active]:opacity-100',
        )}
      />
    </TabsPrimitive.Trigger>
  )
}

export function TabsContent({
  className,
  ...props
}: React.ComponentPropsWithoutRef<typeof TabsPrimitive.Content>) {
  return <TabsPrimitive.Content className={cn('pt-5 outline-none', className)} {...props} />
}

/* ---------------------------------------------------------------- Tooltip */

export function TooltipProvider({ children }: { children: React.ReactNode }) {
  return (
    <TooltipPrimitive.Provider delayDuration={260} skipDelayDuration={400}>
      {children}
    </TooltipPrimitive.Provider>
  )
}

/**
 * Tooltip for supplementary hints. Icon-only controls must still carry their
 * own aria-label — a tooltip never replaces an accessible name.
 */
export function Tooltip({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <TooltipPrimitive.Root>
      <TooltipPrimitive.Trigger asChild>{children}</TooltipPrimitive.Trigger>
      <TooltipPrimitive.Portal>
        <TooltipPrimitive.Content
          sideOffset={6}
          className={cn(
            'z-50 max-w-xs rounded-lg border border-line-strong bg-overlay px-2.5 py-1.5',
            'text-xs leading-relaxed text-ink shadow-[var(--e-overlay)]',
          )}
        >
          {label}
          <TooltipPrimitive.Arrow className="fill-[var(--c-line-strong)]" />
        </TooltipPrimitive.Content>
      </TooltipPrimitive.Portal>
    </TooltipPrimitive.Root>
  )
}

/* -------------------------------------------------------------- Disclosure */

/**
 * Expandable technical detail.
 *
 * Built on <details> to keep native semantics and keyboard behaviour; the
 * height animates via a grid-rows transition, which needs no JS measurement
 * and cannot cause layout shift elsewhere on the page.
 */
export function Disclosure({
  summary,
  children,
  defaultOpen = false,
  className,
}: {
  summary: React.ReactNode
  children: React.ReactNode
  defaultOpen?: boolean
  className?: string
}) {
  const [open, setOpen] = React.useState(defaultOpen)

  return (
    <details
      open={open}
      onToggle={(event) => setOpen((event.currentTarget as HTMLDetailsElement).open)}
      className={cn('group', className)}
    >
      <summary
        className={cn(
          'flex cursor-pointer items-center gap-2 rounded-lg px-2 py-1.5 text-sm text-ink',
          'transition-colors duration-[var(--dur-fast)] hover:bg-raised',
        )}
      >
        <ChevronRight
          className={cn(
            'size-3.5 shrink-0 text-ink-faint',
            'transition-transform duration-[var(--dur-base)] ease-[var(--ease-out-soft)]',
            'group-open:rotate-90',
          )}
          aria-hidden
        />
        <span className="min-w-0 flex-1">{summary}</span>
      </summary>
      <div
        className={cn(
          'grid transition-[grid-template-rows] duration-[var(--dur-base)] ease-[var(--ease-out-soft)]',
          open ? 'grid-rows-[1fr]' : 'grid-rows-[0fr]',
        )}
      >
        <div className="overflow-hidden">
          <div className="pt-2 pl-2">{children}</div>
        </div>
      </div>
    </details>
  )
}
