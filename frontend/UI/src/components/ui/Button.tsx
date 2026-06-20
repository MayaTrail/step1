import type { ReactNode, MouseEvent, CSSProperties } from 'react'

/**
 * MayaTrail Button.
 *
 * Tailwind-class adaptation of the design-system `components/core/Button`
 * (claude.ai/design). Hover is an opacity/translate shift (the signature
 * Raycast interaction), never a hard color swap on the bordered/ghost variants.
 *
 * Variants:
 *   primary   — solid Raycast Red, the product's main action
 *   cta       — semi-transparent white pill on dark text (marketing / connect)
 *   secondary — transparent, bordered
 *   ghost     — no chrome, dim text that brightens on hover
 *   danger    — transparent, danger-tinted (destructive actions, e.g. sign out)
 */

type ButtonVariant = 'primary' | 'cta' | 'secondary' | 'ghost' | 'danger'
type ButtonSize = 'sm' | 'md' | 'lg'

interface ButtonProps {
    children: ReactNode
    variant?: ButtonVariant
    size?: ButtonSize
    /** Leading icon node (an SVG); sits left of the label. */
    icon?: ReactNode
    disabled?: boolean
    type?: 'button' | 'submit' | 'reset'
    className?: string
    style?: CSSProperties
    onClick?: (e: MouseEvent<HTMLButtonElement>) => void
}

const sizeClass: Record<ButtonSize, string> = {
    sm: 'px-3.5 py-2 text-sm rounded-btn',
    md: 'px-5 py-2.5 text-sm rounded-btn',
    lg: 'px-6 py-3 text-base rounded-pill',
}

const variantClass: Record<ButtonVariant, string> = {
    primary: 'bg-danger text-white border-transparent hover:opacity-90',
    cta: 'bg-white/80 text-button-fg border-transparent rounded-pill hover:bg-white',
    secondary: 'bg-transparent text-content-primary border-white/15 hover:bg-white/5 hover:border-border-active',
    ghost: 'bg-transparent text-content-dim border-transparent hover:text-content-primary',
    danger: 'bg-transparent text-danger border-danger/20 hover:bg-danger/10',
}

export function Button({
    children,
    variant = 'primary',
    size = 'md',
    icon = null,
    disabled = false,
    type = 'button',
    className = '',
    style,
    onClick,
}: ButtonProps) {
    return (
        <button
            type={type}
            disabled={disabled}
            onClick={onClick}
            style={style}
            className={`inline-flex items-center justify-center gap-2 whitespace-nowrap
                font-display font-semibold tracking-btn border select-none
                transition-all active:translate-y-px
                ${disabled ? 'opacity-40 cursor-not-allowed' : 'cursor-pointer'}
                ${sizeClass[size]} ${variantClass[variant]} ${className}`}
        >
            {icon && <span className="inline-flex shrink-0">{icon}</span>}
            {children}
        </button>
    )
}
