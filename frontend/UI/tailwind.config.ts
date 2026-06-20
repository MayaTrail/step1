import type { Config } from 'tailwindcss'

export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  darkMode: ['class', '[data-theme="dark"]'],
  theme: {
    extend: {
      colors: {
        /*
         * Brand & semantic — Raycast design system
         * danger = Raycast Red (#FF6363): brand accent, error states, critical highlights
         * Used for punctuation only, not pervasively.
         */
        danger: {
          DEFAULT: '#FF6363',
          glow: 'rgba(255, 99, 99, 0.15)',
          dim: 'rgba(255, 99, 99, 0.08)',
        },
        safe: {
          DEFAULT: '#5fc992',
          glow: 'rgba(95, 201, 146, 0.15)',
          dim: 'rgba(95, 201, 146, 0.08)',
        },
        warning: {
          DEFAULT: '#ffbc33',
          glow: 'rgba(255, 188, 51, 0.15)',
          dim: 'rgba(255, 188, 51, 0.08)',
        },
        accent: {
          // Raycast Blue — interactive accent: links, focus states, selected items
          blue: '#55b3ff',
          'blue-glow': 'hsla(202, 100%, 67%, 0.15)',
        },

        // Theme-aware surface scale — resolved via CSS custom properties
        surface: {
          deep:     'var(--surface-deep)',
          base:     'var(--surface-base)',
          card:     'var(--surface-card)',
          elevated: 'var(--surface-elevated)',
        },

        // Theme-aware text scale
        content: {
          primary:   'var(--content-primary)',
          secondary: 'var(--content-secondary)',
          dim:       'var(--content-dim)',
          muted:     'var(--content-muted)',
        },

        // Theme-aware borders — white at low opacity on dark, black at low opacity on light
        border: {
          subtle:  'var(--border-subtle)',
          DEFAULT: 'var(--border-default)',
          active:  'var(--border-active)',
        },

        // Dashboard semantic accent colors
        cyan:   'var(--cyan)',
        orange: 'var(--orange)',
        purple: 'var(--purple)',
        green:  'var(--green)',
        yellow: 'var(--yellow)',
        blue:   'var(--blue)',

        // Dark foreground for buttons on light/translucent surfaces (DESIGN.md "Button Foreground")
        'button-fg': '#18191a',
      },

      fontSize: {
        // Micro mono labels (account ID caption, connection-mode eyebrow) — 10px
        '2xs': ['10px', { lineHeight: '1.4' }],
      },

      letterSpacing: {
        // px-based tracking scale from DESIGN.md typography rules
        body:  '0.2px',  // body baseline
        btn:   '0.3px',  // buttons, nav links
        caps:  '0.5px',  // small uppercase tags
        label: '1px',    // uppercase mono section labels
      },

      backgroundImage: {
        // Keyboard key-cap gradient (DESIGN.md gradient system) — used on the avatar tile
        key: 'linear-gradient(180deg, #121212 0%, #0d0d0d 100%)',
      },

      fontFamily: {
        /*
         * Inter: primary font for all UI text (headings, body, buttons, captions).
         * OpenType features (calt, kern, liga, ss03) are enabled globally in globals.css.
         * sans is also remapped so Tailwind's default font-sans resolves to Inter.
         */
        sans:    ['Inter', 'system-ui', 'sans-serif'],
        display: ['Inter', 'system-ui', 'sans-serif'],
        body:    ['Inter', 'system-ui', 'sans-serif'],
        /*
         * Geist Mono: code blocks, terminal output, technical labels.
         * Fallback chain matches Raycast's spec.
         */
        mono: ['Geist Mono', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'monospace'],
      },

      borderRadius: {
        /*
         * Raycast border radius scale:
         *   btn (8px)  — inputs, secondary buttons, badges
         *   card (16px) — standard cards, product screenshots
         *   pill (86px) — primary CTA buttons, nav CTAs
         */
        btn:  '8px',
        card: '16px',
        pill: '86px',
      },

      boxShadow: {
        /*
         * macOS-native multi-layer shadow system.
         * Every shadow has both an outer ring and an inset companion — never single-layer.
         *   ring   — double-ring card containment (replaces traditional borders)
         *   button — macOS button press: white highlight top, dark inset bottom
         *   float  — floating panels with glow
         */
        ring:   'rgb(27, 28, 30) 0px 0px 0px 1px, rgb(7, 8, 10) 0px 0px 0px 1px inset',
        button: 'rgba(255, 255, 255, 0.05) 0px 1px 0px 0px inset, rgba(255, 255, 255, 0.25) 0px 0px 0px 1px, rgba(0, 0, 0, 0.2) 0px -1px 0px 0px inset',
        float:  'rgba(0, 0, 0, 0.5) 0px 0px 0px 2px, rgba(255, 255, 255, 0.19) 0px 0px 14px, rgba(255, 255, 255, 0.05) 0px 1px 0px 0px inset',
      },

      keyframes: {
        fadeIn: {
          from: { opacity: '0' },
          to:   { opacity: '1' },
        },
        fadeSlideIn: {
          from: { opacity: '0', transform: 'translateY(-8px)' },
          to:   { opacity: '1', transform: 'translateY(0)' },
        },
        modalIn: {
          from: { opacity: '0', transform: 'scale(0.95) translateY(10px)' },
          to:   { opacity: '1', transform: 'scale(1) translateY(0)' },
        },
        slideUp: {
          from: { opacity: '0', transform: 'translateY(20px)' },
          to:   { opacity: '1', transform: 'translateY(0)' },
        },
        spin: {
          to: { transform: 'rotate(360deg)' },
        },
      },

      animation: {
        fadeIn:      'fadeIn 0.3s ease-out',
        fadeSlideIn: 'fadeSlideIn 0.3s ease-out',
        modalIn:     'modalIn 0.25s ease-out',
        slideUp:     'slideUp 0.3s ease-out',
        spin:        'spin 0.6s linear infinite',
      },
    },
  },
  plugins: [],
} satisfies Config
