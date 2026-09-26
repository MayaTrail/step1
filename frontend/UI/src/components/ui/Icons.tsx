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

export const IconHome = (p: IconProps) => (
    <Icon {...p}>
        <path d="m3 10 9-7 9 7" />
        <path d="M5 9v11a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1V9" />
        <path d="M9 21v-6h6v6" />
    </Icon>
)

export const IconSearch = (p: IconProps) => (
    <Icon {...p}>
        <circle cx="11" cy="11" r="7" />
        <path d="m21 21-4.3-4.3" />
    </Icon>
)

export const IconClipboard = (p: IconProps) => (
    <Icon {...p}>
        <rect x="6" y="4" width="12" height="17" rx="2" />
        <path d="M9 4V3a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v1" />
        <path d="M9 11h6M9 15h4" />
    </Icon>
)

export const IconBook = (p: IconProps) => (
    <Icon {...p}>
        <path d="M5 4a2 2 0 0 1 2-2h12v15H7a2 2 0 0 0-2 2V4Z" />
        <path d="M5 19a2 2 0 0 1 2-2h12v4H7a2 2 0 0 1-2-2Z" />
    </Icon>
)

export const IconBarChart = (p: IconProps) => (
    <Icon {...p}>
        <path d="M3 21h18" />
        <path d="M6 21V11M12 21V5M18 21v-8" />
    </Icon>
)

export const IconBroadcast = (p: IconProps) => (
    <Icon {...p}>
        <circle cx="12" cy="12" r="2" />
        <path d="M8.5 15.5a5 5 0 0 1 0-7M15.5 8.5a5 5 0 0 1 0 7" />
        <path d="M5.5 18.5a9 9 0 0 1 0-13M18.5 5.5a9 9 0 0 1 0 13" />
    </Icon>
)

export const IconExternalLink = (p: IconProps) => (
    <Icon {...p}>
        <path d="M14 4h6v6" />
        <path d="M20 4 11 13" />
        <path d="M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5" />
    </Icon>
)

/*
 * Solid rather than outlined, unlike the rest of the set. At 17px in the top
 * bar an outlined bell reads as a smudge, and this one carries an unread count
 * beside it that needs a confident shape to sit against.
 */
export const IconBell = ({ size = 18, ...rest }: IconProps) => (
    <svg
        width={size}
        height={size}
        viewBox="0 0 24 24"
        fill="currentColor"
        stroke="none"
        {...rest}
    >
        <path d="M12 2.6a5.9 5.9 0 0 0-5.9 5.9v3.3c0 .9-.35 1.76-.98 2.4l-.72.73a1.2 1.2 0 0 0 .85 2.05h13.5a1.2 1.2 0 0 0 .85-2.05l-.72-.73a3.4 3.4 0 0 1-.98-2.4V8.5A5.9 5.9 0 0 0 12 2.6Z" />
        <path d="M9.7 19.1a2.45 2.45 0 0 0 4.6 0Z" />
    </svg>
)

export const IconCheck = (p: IconProps) => (
    <Icon {...p}>
        <path d="m4 12 5 5L20 6" />
    </Icon>
)

export const IconClose = (p: IconProps) => (
    <Icon {...p}>
        <path d="M6 6 18 18M18 6 6 18" />
    </Icon>
)

/**
 * Drawn for the emulation detail tabs, where the existing set had no honest
 * match. Reusing IconShield for MITRE Mapping was the alternative, and it
 * would have collided with the prevention shields on the same page, where a
 * shield already carries a three-state security meaning.
 */

/** Attack Path: a route through connected waypoints. */
export const IconRoute = (p: IconProps) => (
    <Icon {...p}>
        <circle cx="5" cy="18" r="2.5" />
        <circle cx="19" cy="6" r="2.5" />
        <path d="M7.5 18h5a4 4 0 0 0 0-8H11a4 4 0 0 1 0-8h5.5" />
    </Icon>
)

/** MITRE Mapping: a technique matrix. */
export const IconMatrix = (p: IconProps) => (
    <Icon {...p}>
        <rect x="3" y="3" width="7" height="7" rx="1.5" />
        <rect x="14" y="3" width="7" height="7" rx="1.5" />
        <rect x="3" y="14" width="7" height="7" rx="1.5" />
        <rect x="14" y="14" width="7" height="7" rx="1.5" />
    </Icon>
)

/** Ask AI: the conventional generative sparkle. */
export const IconSparkle = (p: IconProps) => (
    <Icon {...p}>
        <path d="M12 3.5 13.9 9l5.5 1.9-5.5 1.9L12 18.3l-1.9-5.5L4.6 11 10.1 9z" />
        <path d="M18.5 16.5 19 18l1.5.5-1.5.5-.5 1.5-.5-1.5L16.5 18l1.5-.5z" />
    </Icon>
)

/** Past Findings: a clock wound backwards. */
export const IconHistory = (p: IconProps) => (
    <Icon {...p}>
        <path d="M3.5 9A9 9 0 1 1 3 12" />
        <path d="M3 4.5V9h4.5" />
        <path d="M12 7.5V12l3 1.8" />
    </Icon>
)
