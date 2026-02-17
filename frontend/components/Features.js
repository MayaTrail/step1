/* Features Section — 3-column grid with emoji icons and category tags */

function FeaturesSection() {
  var features = [
    { icon: '\uD83C\uDFAF', name: 'APT Emulation in Cloud', desc: 'Emulate full APT campaigns in your live AWS environment. Real adversary TTPs executed safely to test your defenses end-to-end.', tag: 'Core', cyan: false },
    { icon: '\uD83D\uDD00', name: 'Attack Path Emulation', desc: 'Run individual attack paths to isolate specific weaknesses. Test lateral movement, privilege escalation, and data exfiltration chains.', tag: 'Simulation', cyan: true },
    { icon: '\uD83D\uDCCB', name: 'IR Playbooks', desc: 'Every emulated attack ships with a tailored incident response playbook \u2014 giving your SOC actionable, step-by-step response procedures.', tag: 'Response', cyan: false },
    { icon: '\uD83D\uDEE1\uFE0F', name: 'Detection Engineering Rules', desc: 'Auto-generate detection rules for each emulated technique. Sigma, Splunk SPL, and CloudWatch-compatible outputs out of the box.', tag: 'Detection', cyan: true },
    { icon: '\uD83D\uDCCA', name: 'Graphical Attack Visualization', desc: 'Interactive kill-chain graphs that map each emulation step visually. See the full attack timeline, pivots, and impact zones.', tag: 'Visualization', cyan: false },
    { icon: '\uD83D\uDDFA\uFE0F', name: 'MITRE ATT\u0026CK Mapping', desc: 'Every technique mapped to MITRE ATT\u0026CK IDs. Full coverage visibility, gap analysis, and technique heatmaps for your environment.', tag: 'Framework', cyan: true },
    { icon: '\uD83D\uDEA7', name: 'Organizational Guardrails', desc: 'Policy-driven guardrails that translate emulation insights into concrete blocking rules \u2014 SCPs, IAM policies, and network controls.', tag: 'Prevention', cyan: false }
  ];

  return React.createElement('section', {
    id: 'features',
    className: 'page-section features-bg',
    'aria-labelledby': 'features-heading'
  },
    React.createElement('div', { className: 'section-container' },
      React.createElement('div', { className: 'reveal' },
        React.createElement('div', { className: 'section-eyebrow' }, 'Core Capabilities'),
        React.createElement('h2', {
          id: 'features-heading',
          className: 'section-title'
        }, 'Everything You Need to', React.createElement('br'), 'Harden Your Cloud'),
        React.createElement('p', { className: 'section-desc' },
          'MayaTrail provides an end-to-end adversary emulation platform purpose-built for cloud infrastructure \u2014 from attack simulation to detection rules.'
        )
      ),
      React.createElement('div', { className: 'features-grid' },
        features.map(function(f, i) {
          return React.createElement('div', {
            key: i,
            className: 'feature-card reveal' + (f.cyan ? ' cyan-accent' : '')
          },
            React.createElement('div', { className: 'feature-icon-box' }, f.icon),
            React.createElement('div', { className: 'feature-name' }, f.name),
            React.createElement('div', { className: 'feature-desc' }, f.desc),
            React.createElement('span', { className: 'feature-tag' }, f.tag)
          );
        })
      )
    )
  );
}
