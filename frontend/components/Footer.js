/* Footer — Minimal dark footer matching reference design */

function Footer() {
  return React.createElement('footer', {
    className: 'site-footer',
    role: 'contentinfo'
  },
    React.createElement('div', { className: 'footer-content' },
      React.createElement('div', { className: 'footer-logo-text' }, '\u26E8 MayaTrail'),
      React.createElement('div', { className: 'footer-copyright' },
        '\u00A9 2025 MayaTrail. Cloud security through adversary emulation.'
      ),
      React.createElement('ul', { className: 'footer-links-list' },
        React.createElement('li', null,
          React.createElement('a', { href: '#features' }, 'Features')
        ),
        React.createElement('li', null,
          React.createElement('a', { href: '#services' }, 'Services')
        ),
        React.createElement('li', null,
          React.createElement('a', { href: '#contact' }, 'Contact')
        )
      )
    )
  );
}
