import type { Config } from 'tailwindcss'

export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  darkMode: ['class', '[data-theme="dark"]'],
  theme: {
    extend: {
      colors: {
        danger: {
          DEFAULT: '#ff2244',
          glow: 'rgba(255, 34, 68, 0.4)',
          dim: 'rgba(255, 34, 68, 0.15)',
        },
        safe: {
          DEFAULT: '#00e676',
          glow: 'rgba(0, 230, 118, 0.4)',
          dim: 'rgba(0, 230, 118, 0.12)',
        },
        accent: {
          blue: '#00b4d8',
          cyan: '#48e8c8',
        },
        // Theme-aware colors via CSS custom properties
        surface: {
          deep: 'var(--surface-deep)',
          base: 'var(--surface-base)',
          card: 'var(--surface-card)',
          elevated: 'var(--surface-elevated)',
        },
        content: {
          primary: 'var(--content-primary)',
          secondary: 'var(--content-secondary)',
          dim: 'var(--content-dim)',
        },
        border: {
          subtle: 'var(--border-subtle)',
          DEFAULT: 'var(--border-default)',
          active: 'var(--border-active)',
        },
        // Dashboard accent colors
        cyan: 'var(--cyan)',
        orange: 'var(--orange)',
        purple: 'var(--purple)',
        green: 'var(--green)',
      },
      fontFamily: {
        display: ['Outfit', 'sans-serif'],
        body: ['Space Grotesk', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
      },
      borderRadius: {
        card: '16px',
        btn: '12px',
      },
      keyframes: {
        fadeIn: {
          from: { opacity: '0' },
          to: { opacity: '1' },
        },
        modalIn: {
          from: { opacity: '0', transform: 'scale(0.95) translateY(10px)' },
          to: { opacity: '1', transform: 'scale(1) translateY(0)' },
        },
        slideUp: {
          from: { opacity: '0', transform: 'translateY(20px)' },
          to: { opacity: '1', transform: 'translateY(0)' },
        },
        spin: {
          to: { transform: 'rotate(360deg)' },
        },
      },
      animation: {
        fadeIn: 'fadeIn 0.3s ease-out',
        modalIn: 'modalIn 0.25s ease-out',
        slideUp: 'slideUp 0.3s ease-out',
        spin: 'spin 0.6s linear infinite',
      },
    },
  },
  plugins: [],
} satisfies Config
