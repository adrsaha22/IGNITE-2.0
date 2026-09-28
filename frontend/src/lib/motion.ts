/**
 * Shared motion language.
 *
 * One set of variants and transitions so entrances, tab changes and list
 * staggers feel consistent. Every helper collapses to an instant, motionless
 * state when the user prefers reduced motion.
 */

import { useEffect, useState } from 'react'
import type { Transition, Variants } from 'motion/react'

/** Tracks the OS reduced-motion preference, live. */
export function useReducedMotion(): boolean {
  const [reduced, setReduced] = useState(() => {
    try {
      return window.matchMedia('(prefers-reduced-motion: reduce)').matches
    } catch {
      return false
    }
  })

  useEffect(() => {
    let media: MediaQueryList
    try {
      media = window.matchMedia('(prefers-reduced-motion: reduce)')
    } catch {
      return
    }
    const onChange = (event: MediaQueryListEvent) => setReduced(event.matches)
    media.addEventListener('change', onChange)
    return () => media.removeEventListener('change', onChange)
  }, [])

  return reduced
}

export const EASE_OUT: Transition = {
  duration: 0.34,
  ease: [0.22, 1, 0.36, 1],
}

export const EASE_FAST: Transition = {
  duration: 0.18,
  ease: [0.22, 1, 0.36, 1],
}

/** Entrance for a panel or section. */
export const rise: Variants = {
  hidden: { opacity: 0, y: 8 },
  visible: { opacity: 1, y: 0, transition: EASE_OUT },
}

/** Container that staggers its children's entrances. */
export const stagger: Variants = {
  hidden: {},
  visible: { transition: { staggerChildren: 0.045, delayChildren: 0.02 } },
}

/** Tab panel cross-fade. */
export const tabPanel: Variants = {
  hidden: { opacity: 0, y: 6 },
  visible: { opacity: 1, y: 0, transition: EASE_OUT },
}

/**
 * Strip all movement when reduced motion is requested: elements appear in
 * their final state with no transition.
 */
export function motionSafe<T extends Variants>(variants: T, reduced: boolean): Variants {
  if (!reduced) return variants
  return {
    hidden: { opacity: 1 },
    visible: { opacity: 1, transition: { duration: 0 } },
  }
}
