/* Add-On Services — 2-column grid with large numbers and tags */

function ServicesSection() {
  var services = [
    {
      number: '01',
      name: 'SOC Team Training for IR',
      desc: 'Hands-on incident response training using real MayaTrail emulations. Your analysts practice triage, containment, and recovery against live adversary simulations.',
      tag: 'Training'
    },
    {
      number: '02',
      name: 'Detection Engineering Review',
      desc: 'We review your detection pipeline end-to-end \u2014 log sources, rule logic, alert fidelity \u2014 and help engineer high-signal detections that actually catch threats.',
      tag: 'Engineering'
    },
    {
      number: '03',
      name: 'Cloud Red Teaming',
      desc: 'Adversary-simulation engagements conducted by our offensive security team. Real objectives, real TTPs, real findings \u2014 tailored to your cloud environment.',
      tag: 'Offensive'
    },
    {
      number: '04',
      name: 'Infrastructure Security Review',
      desc: 'Deep assessment of your AWS architecture \u2014 IAM policies, network design, encryption, logging, and compliance posture. Actionable hardening recommendations.',
      tag: 'Assessment'
    },
    {
      number: '05',
      name: 'Security Tooling \u0026 AWS Setup',
      desc: 'We help startups and organizations set up security tools and establish secure configurations for AWS cloud infrastructure from day one \u2014 GuardDuty, Security Hub, CloudTrail, and beyond.',
      tag: 'Setup'
    }
  ];

  return React.createElement('section', {
    id: 'services',
    className: 'page-section addons-bg',
    'aria-labelledby': 'services-heading'
  },
    React.createElement('div', { className: 'section-container' },
      React.createElement('div', { className: 'reveal' },
        React.createElement('div', { className: 'section-eyebrow' }, 'Professional Services'),
        React.createElement('h2', {
          id: 'services-heading',
          className: 'section-title'
        }, 'Add-On Services'),
        React.createElement('p', { className: 'section-desc' },
          'Extend MayaTrail with hands-on expertise. Our team embeds with yours to elevate your security operations.'
        )
      ),
      React.createElement('div', { className: 'addons-grid' },
        services.map(function(s, i) {
          return React.createElement('div', {
            key: i,
            className: 'addon-card reveal'
          },
            React.createElement('div', { className: 'addon-number' }, s.number),
            React.createElement('div', null,
              React.createElement('div', { className: 'addon-name' }, s.name),
              React.createElement('div', { className: 'addon-desc' }, s.desc),
              React.createElement('span', { className: 'addon-tag' }, s.tag)
            )
          );
        })
      )
    )
  );
}
