import type { SVGProps } from 'react'

/**
 * MayaTrail line-icon set.
 *
 * Tailwind/TSX adaptation of the design-system `ui_kits/console/icons.jsx`
 * (claude.ai/design): clean 1.6px line icons drawn in `currentColor` so they
 * inherit text color and respond to opacity hovers. Size via the `size` prop
 * (default 18) or a width/height utility class. No emoji in chrome.
 */

interface IconProps extends Omit<SVGProps<SVGSVGElement>, 'children'> {
    size?: number
}

function Icon({ size = 18, children, ...rest }: IconProps & { children: React.ReactNode }) {
    return (
        <svg
            width={size}
            height={size}
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth={1.6}
            strokeLinecap="round"
            strokeLinejoin="round"
            {...rest}
        >
            {children}
        </svg>
    )
}

export const IconChevron = (p: IconProps) => (
    <Icon {...p}><path d="m9 6 6 6-6 6" /></Icon>
)

export const IconGear = (p: IconProps) => (
    <Icon {...p}>
        <circle cx="12" cy="12" r="3" />
        <path d="M12 2v3M12 19v3M2 12h3M19 12h3M5 5l2 2M17 17l2 2M19 5l-2 2M7 17l-2 2" />
    </Icon>
)

export const IconShield = (p: IconProps) => (
    <Icon {...p}><path d="M12 3 5 6v6c0 4 3 7 7 9 4-2 7-5 7-9V6l-7-3Z" /></Icon>
)

export const IconCloud = (p: IconProps) => (
    <Icon {...p}><path d="M7 18a4 4 0 0 1 0-8 5 5 0 0 1 9.6-1.3A3.5 3.5 0 0 1 17 18H7Z" /></Icon>
)

export const IconCopy = (p: IconProps) => (
    <Icon {...p}>
        <rect x="9" y="9" width="11" height="11" rx="2" />
        <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
    </Icon>
)

export const IconPencil = (p: IconProps) => (
    <Icon {...p}>
        <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7" />
        <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5Z" />
    </Icon>
)

export const IconLogout = (p: IconProps) => (
    <Icon {...p}>
        <path d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 0 1-3 3H6a3 3 0 0 1-3-3V7a3 3 0 0 1 3-3h4a3 3 0 0 1 3 3v1" />
    </Icon>
)

export const IconFlask = (p: IconProps) => (
    <Icon {...p}>
        <path d="M9 3h6M10 3v6L5 19a1.5 1.5 0 0 0 1.4 2h11.2A1.5 1.5 0 0 0 19 19l-5-10V3" />
        <path d="M7.5 14h9" />
    </Icon>
)

export const IconClock = (p: IconProps) => (
    <Icon {...p}>
        <circle cx="12" cy="12" r="8" />
        <path d="M12 8v4l3 2" />
    </Icon>
)

export const IconInfo = (p: IconProps) => (
    <Icon {...p}>
        <circle cx="12" cy="12" r="9" />
        <path d="M12 11v5M12 8h.01" />
    </Icon>
)

export const IconAlert = (p: IconProps) => (
    <Icon {...p}>
        <path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z" />
        <path d="M12 9v4M12 17h.01" />
    </Icon>
)

export const IconLaunch = (p: IconProps) => (
    <Icon {...p}>
        <path d="M21 3 10 14" />
        <path d="M21 3 14.5 21l-3.5-7-7-3.5L21 3Z" />
    </Icon>
)

export const IconTrash = (p: IconProps) => (
    <Icon {...p}>
        <path d="M4 7h16" />
        <path d="M9 7V5a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2" />
        <path d="M6 7l1 13a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1l1-13" />
    </Icon>
)

export const IconLayers = (p: IconProps) => (
    <Icon {...p}>
        <path d="m12 3 9 5-9 5-9-5 9-5Z" />
        <path d="m3 13 9 5 9-5" />
    </Icon>
)

export const IconActivity = (p: IconProps) => (
    <Icon {...p}><path d="M3 12h4l3 8 4-16 3 8h4" /></Icon>
)
