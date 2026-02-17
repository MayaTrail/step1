/* How It Works — 4-step grid with counter + ghost numbers */

function HowItWorksSection() {
  var steps = [
    {
      number: 'Step 01',
      title: 'Connect Your Environment',
      desc: 'Integrate MayaTrail with your AWS environment using a read-only role. Zero impact on production workloads.'
    },
    {
      number: 'Step 02',
      title: 'Select Attack Scenarios',
      desc: 'Choose from a curated library of real-world APT campaigns or build custom attack paths tailored to your infrastructure.'
    },
    {
      number: 'Step 03',
      title: 'Run Emulations',
      desc: 'Execute adversary techniques safely. MayaTrail generates full attack telemetry, detection rules, and visual attack graphs in real-time.'
    },
    {
      number: 'Step 04',
      title: 'Harden \u0026 Respond',
      desc: 'Deploy generated detections, activate guardrails, and use IR playbooks to close gaps before real adversaries exploit them.'
    }
  ];

  return React.createElement('section', {
    id: 'how-it-works',
    className: 'page-section',
    'aria-labelledby': 'hiw-heading'
  },
    React.createElement('div', { className: 'section-container' },
      React.createElement('div', { className: 'reveal' },
        React.createElement('div', { className: 'section-eyebrow' }, 'How It Works'),
        React.createElement('h2', {
          id: 'hiw-heading',
          className: 'section-title'
        }, 'From Emulation', React.createElement('br'), 'to Protection'),
        React.createElement('p', { className: 'section-desc' },
          'Four steps to transform your cloud security posture. No agents, no disruption.'
        )
      ),
      React.createElement('div', { className: 'steps-grid' },
        steps.map(function(s, i) {
          return React.createElement('div', {
            key: i,
            className: 'step-card reveal'
          },
            React.createElement('div', { className: 'step-number' }, s.number),
            React.createElement('div', { className: 'step-title' }, s.title),
            React.createElement('div', { className: 'step-desc' }, s.desc)
          );
        })
      )
    )
  );
}
