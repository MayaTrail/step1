/* Navbar — Reference design: fixed, blurred, with logo-icon-box + nav-cta */

function Navbar({ isProtected }) {
  const [menuOpen, setMenuOpen] = React.useState(false);

  const links = [
    { label: 'Features', href: '#features' },
    { label: 'How It Works', href: '#how-it-works' },
    { label: 'MITRE Mapping', href: '#mitre' },
    { label: 'Services', href: '#services' }
  ];

  return React.createElement('nav', {
    className: 'main-nav',
    'aria-label': 'Primary navigation'
  },
    // Logo
    React.createElement('a', { href: '#hero', className: 'nav-logo' },
      React.createElement('div', {
        className: 'logo-icon-box' + (isProtected ? ' safe' : '')
      }, '\u26E8'),
      'MayaTrail'
    ),
    // Desktop links
    React.createElement('ul', { className: 'nav-links-list' },
      links.map(function(l) {
        return React.createElement('li', { key: l.label },
          React.createElement('a', { href: l.href }, l.label)
        );
      }),
      React.createElement('li', null,
        React.createElement('a', {
          href: '#contact',
          className: 'nav-cta-btn' + (isProtected ? ' safe' : '')
        }, 'Request Demo')
      )
    ),
    // Mobile hamburger
    React.createElement('button', {
      className: 'mobile-menu-btn',
      onClick: function() { setMenuOpen(!menuOpen); },
      'aria-label': menuOpen ? 'Close menu' : 'Open menu',
      'aria-expanded': menuOpen
    },
      React.createElement('span', null),
      React.createElement('span', null),
      React.createElement('span', null)
    ),
    // Mobile dropdown
    menuOpen && React.createElement('div', { className: 'mobile-menu-dropdown' },
      links.map(function(l) {
        return React.createElement('a', {
          key: l.label,
          href: l.href,
          onClick: function() { setMenuOpen(false); }
        }, l.label);
      }),
      React.createElement('a', {
        href: '#contact',
        onClick: function() { setMenuOpen(false); },
        className: 'nav-cta-btn' + (isProtected ? ' safe' : ''),
        style: { display: 'inline-block', marginTop: '12px', textAlign: 'center' }
      }, 'Request Demo')
    )
  );
}
