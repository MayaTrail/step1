# MayaTrail — deployment / link map

How the site files connect, so you know exactly what to deploy and what is optional.

## Deploy these (the public website)

| File | Role | Reached from | Links out to |
|------|------|--------------|--------------|
| `index.html` | Landing / Platform (entry point) | direct URL / Pages root | scenarios, run, coverage, pricing, research, playbook (via Run links), mailto, github |
| `scenarios.html` | Attack-chain catalogue | nav, footer | index, run, coverage, pricing, research |
| `run.html` | AMBERSQUID emulation playback | nav, footer, index hero/CTAs | playbook, coverage, index |
| `coverage.html` | MITRE ATT&CK coverage grid | nav, footer | index, github (repo = source of truth) |
| `pricing.html` | Open-core pricing | nav, footer | mailto, github |
| `research.html` | Research (coming-soon placeholder) | nav, footer | mailto, run |
| `playbook.html` | AMBERSQUID IR playbook | **run.html only** (not in nav) | run, index, coverage |

### Required assets (deploy all)
| File | Used by |
|------|---------|
| `mayatrail-base.css` | every page |
| `landing-vault.jsx` | index.html |
| `tweaks-panel.jsx` | index.html |
| `run-experience.jsx` | run.html |
| `favicon.svg` | every page |
| `logo/` | brand assets (referenced by you, not auto-loaded) |
| `index.html` … | (see above) |

## In the top nav (6 tabs, identical on every page)
index (Platform) · scenarios · run · coverage · pricing · research

## Linked but NOT in the nav
- `playbook.html` — intentionally reachable only from `run.html`. It's a run artifact, not a top-level page. Keep it; just don't add it to the nav.

## External links (no files to deploy)
- `mailto:admin@mayatrail.tech` — Request access / contact, on every page
- `https://github.com/MayaTrail` — repo, in footers + coverage + pricing

## NOT part of the website — do NOT deploy
These live in the project workspace as internal material. They are not linked from any
public page and must stay out of the deployed site:
- Pitch deck, GTM strategy, Battlecards, Demo script, Market analysis
- Logo exploration / lockup working files
- Any `*- standalone.html`, `* v1.*`, screenshots, uploads

## Orphan check
Every deployed page is reachable: the 6 nav pages from anywhere, and `playbook.html`
from `run.html`. No public page is unlinked. If you add a page, add it to the nav in
`mayatrail-base.css`-styled `<nav>` blocks AND the footer on all pages to keep them consistent.
