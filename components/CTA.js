/* CTA Section — Gradient box with radial glow overlays */

function CTASection() {
  return React.createElement('section', {
    id: 'contact',
    className: 'page-section',
    style: { textAlign: 'center' },
    'aria-labelledby': 'cta-heading'
  },
    React.createElement('div', { className: 'section-container' },
      React.createElement('div', { className: 'cta-box reveal' },
        React.createElement('div', { className: 'section-eyebrow' }, 'Get Started'),
        React.createElement('h2', {
          id: 'cta-heading',
          className: 'cta-title'
        }, 'Ready to Test Your', React.createElement('br'), 'Cloud Defenses?'),
        React.createElement('p', { className: 'cta-desc' },
          'Schedule a demo to see MayaTrail emulate APT techniques against your AWS environment in real-time.'
        ),
        React.createElement('div', { className: 'cta-actions' },
          React.createElement('a', {
            href: 'mailto:hello@mayatrail.io',
            className: 'btn-primary-main'
          }, 'Request a Demo'),
          React.createElement('a', {
            href: '#features',
            className: 'btn-secondary-main'
          }, 'Learn More \u2192')
        )
      )
    )
  );
}
