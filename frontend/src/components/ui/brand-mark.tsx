/**
 * The IGNITE brand mark.
 *
 * Matches the favicon in public/favicon.svg so the sidebar, the mobile drawer
 * and the browser tab all show the same logo.
 *
 * The favicon carries a stack of blurred gradient ellipses for its glow. At
 * sidebar size those render as noise and cost a filter pass, so this draws the
 * same bolt silhouette filled with a matching violet gradient instead.
 */

import { cn } from '@/lib/utils'

export function BrandMark({ className }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 48 46"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={cn('shrink-0', className)}
      aria-hidden
      focusable="false"
    >
      <defs>
        {/* Unique id so multiple marks on one page cannot collide. */}
        <linearGradient id="ignite-bolt" x1="0" y1="0" x2="48" y2="46" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#a78bfa" />
          <stop offset="55%" stopColor="#863bff" />
          <stop offset="100%" stopColor="#7e14ff" />
        </linearGradient>
      </defs>
      {/* Bolt path taken from public/favicon.svg. */}
      <path
        fill="url(#ignite-bolt)"
        d="M25.946 44.938c-.664.845-2.021.375-2.021-.698V33.937a2.26 2.26 0 0 0-2.262-2.262H10.287c-.92 0-1.456-1.04-.92-1.788l7.48-10.471c1.07-1.497 0-3.578-1.842-3.578H1.237c-.92 0-1.456-1.04-.92-1.788L10.013.474c.214-.297.556-.474.92-.474h28.894c.92 0 1.456 1.04.92 1.788l-7.48 10.471c-1.07 1.498 0 3.579 1.842 3.579h11.377c.943 0 1.473 1.088.89 1.83L25.947 44.94z"
      />
    </svg>
  )
}
