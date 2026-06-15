import path from 'node:path'
import { fileURLToPath } from 'node:url'

import tsParser from '@typescript-eslint/parser'
import tailwindcss from 'eslint-plugin-tailwindcss'

const __dirname = path.dirname(fileURLToPath(import.meta.url))

/*
 * Design-system enforcement (frontend/UI/DESIGN.md is the source of truth).
 *
 * tailwindcss/no-arbitrary-value blocks bracket syntax like bg-[#1e293b] or
 * shadow-[0_2px_4px], which would bypass the tokens defined in
 * tailwind.config.ts. All colors, shadows, radii, and fonts must come from
 * the named token scales (surface-*, content-*, danger, shadow-ring, etc.).
 */
export default [
  {
    files: ['src/**/*.{ts,tsx}'],
    languageOptions: {
      parser: tsParser,
      parserOptions: {
        ecmaFeatures: { jsx: true },
        sourceType: 'module',
      },
    },
    plugins: { tailwindcss },
    settings: {
      tailwindcss: {
        config: path.join(__dirname, 'tailwind.config.ts'),
      },
    },
    rules: {
      'tailwindcss/no-arbitrary-value': 'error',
      'tailwindcss/no-contradicting-classname': 'error',
    },
  },
]
