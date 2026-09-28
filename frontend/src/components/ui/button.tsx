import * as React from 'react'
import { Slot } from '@radix-ui/react-slot'
import { cva, type VariantProps } from 'class-variance-authority'
import { cn } from '@/lib/utils'

const buttonVariants = cva(
  cn(
    'inline-flex items-center justify-center gap-2 rounded-lg text-sm font-medium whitespace-nowrap',
    'transition-[background-color,border-color,color,box-shadow,transform] duration-[var(--dur-fast)] ease-[var(--ease-out-soft)]',
    // Tactile press feedback — a small scale, never a bounce.
    'active:scale-[0.975]',
    'disabled:pointer-events-none disabled:opacity-45',
    '[&_svg]:size-4 [&_svg]:shrink-0',
  ),
  {
    variants: {
      variant: {
        // The single gradient surface in the app, reserved for the primary action.
        primary:
          'bg-[image:var(--g-primary)] font-semibold text-primary-contrast shadow-[var(--e-primary)] hover:brightness-110',
        outline:
          'border border-line-strong bg-raised text-ink hover:border-primary-line hover:text-primary-bright',
        ghost: 'text-ink-muted hover:bg-raised hover:text-ink',
        danger: 'border border-bad/35 bg-bad-soft text-bad hover:bg-bad/20',
      },
      size: {
        sm: 'h-8 px-3 text-xs',
        md: 'h-9 px-4',
        lg: 'h-11 px-6 text-[0.95rem]',
        icon: 'size-8',
      },
    },
    defaultVariants: { variant: 'outline', size: 'md' },
  },
)

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {
  asChild?: boolean
}

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, asChild = false, ...props }, ref) => {
    const Comp = asChild ? Slot : 'button'
    return (
      <Comp className={cn(buttonVariants({ variant, size }), className)} ref={ref} {...props} />
    )
  },
)
Button.displayName = 'Button'

export { buttonVariants }
