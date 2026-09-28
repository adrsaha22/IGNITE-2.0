/** Minimal toast system for copy/export feedback. */

import * as React from 'react'
import { AnimatePresence, motion } from 'motion/react'
import { AlertTriangle, CheckCircle2, Info } from 'lucide-react'
import { useReducedMotion } from '@/lib/motion'
import { cn } from '@/lib/utils'

type ToastTone = 'success' | 'error' | 'info'

interface Toast {
  id: number
  message: string
  tone: ToastTone
}

const ToastContext = React.createContext<(message: string, tone?: ToastTone) => void>(() => {})

export function useToast() {
  return React.useContext(ToastContext)
}

const ICONS: Record<ToastTone, React.ReactNode> = {
  success: <CheckCircle2 className="size-4 text-ok" />,
  error: <AlertTriangle className="size-4 text-bad" />,
  info: <Info className="size-4 text-primary-bright" />,
}

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = React.useState<Toast[]>([])
  const nextId = React.useRef(0)
  const reduced = useReducedMotion()

  const push = React.useCallback((message: string, tone: ToastTone = 'info') => {
    const id = nextId.current++
    setToasts((current) => [...current, { id, message, tone }])
    window.setTimeout(() => {
      setToasts((current) => current.filter((t) => t.id !== id))
    }, 3200)
  }, [])

  return (
    <ToastContext.Provider value={push}>
      {children}
      <div
        className="pointer-events-none fixed right-4 bottom-4 z-50 flex w-[min(22rem,calc(100vw-2rem))] flex-col gap-2"
        role="status"
        aria-live="polite"
      >
        <AnimatePresence initial={false}>
          {toasts.map((toast) => (
            <motion.div
              key={toast.id}
              initial={reduced ? { opacity: 1 } : { opacity: 0, y: 12, scale: 0.97 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={reduced ? { opacity: 0 } : { opacity: 0, y: 8, scale: 0.98 }}
              transition={reduced ? { duration: 0 } : { duration: 0.22, ease: [0.22, 1, 0.36, 1] }}
              className={cn(
                'sheen pointer-events-auto flex items-center gap-2.5 rounded-xl border bg-overlay px-3.5 py-2.5',
                'text-sm shadow-[var(--e-overlay)]',
                toast.tone === 'success' && 'border-ok/30',
                toast.tone === 'error' && 'border-bad/30',
                toast.tone === 'info' && 'border-line-strong',
              )}
            >
              {ICONS[toast.tone]}
              <span className="text-ink">{toast.message}</span>
            </motion.div>
          ))}
        </AnimatePresence>
      </div>
    </ToastContext.Provider>
  )
}
