# MayaTrail — website

Cloud attack emulation for detection engineers. Static site (HTML + a little React via CDN). No build step.

## Serve it (don't double-click)

Pages load React/Babel from a CDN and pull in local `.jsx`/`.css`, so they must be **served over http(s)**, not opened with `file://`.

**GitHub Pages**
1. Push this folder to a repo.
2. Settings → Pages → deploy from branch (root).
3. The Pages URL opens `index.html` (the landing page) directly.

**Local preview**
```bash
python3 -m http.server 8000   # then open http://localhost:8000
```

## Structure

```
index.html          Landing / Platform (Vault hero, Tweaks panel)
scenarios.html      Attack-chain catalogue
run.html            AMBERSQUID emulation playback (→ playbook.html)
coverage.html       MITRE ATT&CK coverage grid
pricing.html        Open-core pricing
research.html       Research (placeholder)
playbook.html       Generated AMBERSQUID IR playbook (linked from run.html)

mayatrail-base.css  Shared tokens, nav, footer, responsive rules
landing-vault.jsx   Landing hero
tweaks-panel.jsx    Landing tweaks panel
run-experience.jsx  Run page app
favicon.svg         Node-mark favicon
logo/               Logo files (lockups + marks, dark/light)
```

All page links are lowercase and relative. `index.html` is the entry point.

## Brand
- Node-correlation mark · cool `#6aa8ff`, breach `#ff4b6e`, deep (light bg) `#2f5fa8`
- Wordmark: "MayaTrail" with a gentle trail-fade on "Trail"
- Contact: admin@mayatrail.tech · github.com/MayaTrail
