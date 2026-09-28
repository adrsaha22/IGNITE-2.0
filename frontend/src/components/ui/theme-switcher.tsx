/** Dark / Light / System selector rendered as a compact segmented control. */

import { Monitor, Moon, Sun } from 'lucide-react'
import { Tooltip } from './primitives'
import { useTheme, type ThemePreference } from '@/hooks/useTheme'
import { cn } from '@/lib/utils'

const OPTIONS: { value: ThemePreference; label: string; icon: typeof Sun }[] = [
  { value: 'light', label: 'Light', icon: Sun },
  { value: 'dark', label: 'Dark', icon: Moon },
  { value: 'system', label: 'System', icon: Monitor },
]

export function ThemeSwitcher() {
  const { preference, setPreference } = useTheme()

  return (
    <div
      role="radiogroup"
      aria-label="Colour theme"
      className="flex items-center gap-0.5 rounded-lg border border-line bg-raised p-0.5"
    >
      {OPTIONS.map(({ value, label, icon: Icon }) => {
        const active = preference === value
        return (
          <Tooltip key={value} label={`${label} theme`}>
            <button
              role="radio"
              aria-checked={active}
              aria-label={`${label} theme`}
              onClick={() => setPreference(value)}
              className={cn(
                'flex size-7 items-center justify-center rounded-md',
                'transition-colors duration-[var(--dur-fast)] ease-[var(--ease-out-soft)]',
                active
                  ? 'bg-surface text-primary-bright shadow-[var(--e-panel)]'
                  : 'text-ink-faint hover:text-ink',
              )}
            >
              <Icon className="size-3.5" />
            </button>
          </Tooltip>
        )
      })}
    </div>
  )
}
