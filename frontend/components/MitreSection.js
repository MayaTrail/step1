/* MITRE ATT&CK Cloud Matrix — Real structure with APT-attributed techniques */

var MITRE_DATA = {
  tactics: [
    {
      id: 'TA0001',
      name: 'Initial Access',
      techniques: [
        { id: 'T1078', name: 'Valid Accounts', actors: ['scattered-spider', 'dangerdev', 'ambersquid'] },
        { id: 'T1190', name: 'Exploit Public-Facing App', actors: ['ambersquid'] },
        { id: 'T1566.002', name: 'Spearphishing Link', actors: ['dangerdev'] },
        { id: 'T1195.003', name: 'Supply Chain Compromise', actors: ['ambersquid'] }
      ]
    },
    {
      id: 'TA0002',
      name: 'Execution',
      techniques: [
        { id: 'T1059', name: 'Command & Scripting Interpreter', actors: ['ambersquid'] },
        { id: 'T1610', name: 'Deploy Container', actors: ['ambersquid'] },
        { id: 'T1204', name: 'User Execution', actors: ['ambersquid'] },
        { id: 'T1053', name: 'Scheduled Task/Job', actors: ['ambersquid'] }
      ]
    },
    {
      id: 'TA0003',
      name: 'Persistence',
      techniques: [
        { id: 'T1098', name: 'Account Manipulation', actors: ['scattered-spider', 'dangerdev'] },
        { id: 'T1136.003', name: 'Create Cloud Account', actors: ['scattered-spider', 'dangerdev', 'ambersquid'] },
        { id: 'T1098.001', name: 'Additional Cloud Credentials', actors: ['scattered-spider', 'dangerdev', 'ambersquid'] },
        { id: 'T1525', name: 'Implant Container Image', actors: ['ambersquid'] },
        { id: 'T1550.001', name: 'Cross-Account Role Assumption', actors: ['dangerdev'] }
      ]
    },
    {
      id: 'TA0004',
      name: 'Privilege Escalation',
      techniques: [
        { id: 'T1078.004', name: 'Cloud Accounts', actors: ['scattered-spider', 'dangerdev'] },
        { id: 'T1548', name: 'Abuse Elevation Control', actors: ['dangerdev'] },
        { id: 'T1098.001', name: 'Modify Cloud Compute Permissions', actors: ['ambersquid'] }
      ]
    },
    {
      id: 'TA0005',
      name: 'Defense Evasion',
      techniques: [
        { id: 'T1562.008', name: 'Disable Cloud Logs', actors: ['scattered-spider', 'dangerdev'] },
        { id: 'T1562.012', name: 'Disable Cloud Firewall', actors: ['scattered-spider'] },
        { id: 'T1550', name: 'Alternate Auth Material', actors: ['scattered-spider'] },
        { id: 'T1078.004', name: 'Cloud Accounts', actors: ['scattered-spider', 'dangerdev'] }
      ]
    },
    {
      id: 'TA0006',
      name: 'Credential Access',
      techniques: [
        { id: 'T1621', name: 'MFA Bypass / SIM Swap', actors: ['scattered-spider'] },
        { id: 'T1528', name: 'Steal App Access Token', actors: ['dangerdev'] },
        { id: 'T1552.007', name: 'Credentials in Container Image', actors: ['ambersquid'] }
      ]
    },
    {
      id: 'TA0007',
      name: 'Discovery',
      techniques: [
        { id: 'T1526', name: 'Cloud Service Discovery', actors: ['scattered-spider', 'dangerdev', 'ambersquid'] },
        { id: 'T1538', name: 'Cloud Service Dashboard', actors: ['scattered-spider'] },
        { id: 'T1580', name: 'Cloud Infra Discovery', actors: ['scattered-spider', 'ambersquid'] }
      ]
    },
    {
      id: 'TA0008',
      name: 'Lateral Movement',
      techniques: [
        { id: 'T1021.004', name: 'SSH / Remote Services', actors: ['ambersquid'] },
        { id: 'T1550', name: 'Alternate Auth Material', actors: ['scattered-spider'] }
      ]
    },
    {
      id: 'TA0009',
      name: 'Collection',
      techniques: [
        { id: 'T1530', name: 'Data from Cloud Storage', actors: ['scattered-spider'] },
        { id: 'T1213', name: 'Data from Info Repositories', actors: ['scattered-spider'] }
      ]
    },
    {
      id: 'TA0010',
      name: 'Exfiltration',
      techniques: [
        { id: 'T1537', name: 'Transfer Data to Cloud Account', actors: ['scattered-spider', 'ambersquid'] }
      ]
    },
    {
      id: 'TA0040',
      name: 'Impact',
      techniques: [
        { id: 'T1496', name: 'Resource Hijacking', actors: ['dangerdev', 'ambersquid'] },
        { id: 'T1531', name: 'Account Access Removal', actors: ['dangerdev'] }
      ]
    },
    {
      id: 'TA0042',
      name: 'Resource Development',
      techniques: [
        { id: 'T1583.001', name: 'Acquire Domains', actors: ['dangerdev'] },
        { id: 'T1583.006', name: 'Acquire Web Services', actors: ['ambersquid'] }
      ]
    }
  ],
  actors: {
    'scattered-spider': { name: 'Scattered Spider', short: 'SS', color: '#ff2244' },
    'dangerdev': { name: 'DangerDev', short: 'DD', color: '#ff8800' },
    'ambersquid': { name: 'AMBERSQUID', short: 'AS', color: '#a855f7' }
  }
};

// ── Tooltip State (simple hover) ──────────────────────────────
function TechniqueCell({ tech, actors }) {
  var _useState = React.useState(false);
  var hovered = _useState[0];
  var setHovered = _useState[1];

  var actorDots = tech.actors.map(function(aKey) {
    var a = actors[aKey];
    return React.createElement('span', {
      key: aKey,
      className: 'mitre-actor-dot',
      style: { background: a.color },
      title: a.name
    }, a.short);
  });

  var isMultiActor = tech.actors.length > 1;

  return React.createElement('div', {
    className: 'mitre-technique-cell' + (isMultiActor ? ' multi-actor' : ''),
    onMouseEnter: function() { setHovered(true); },
    onMouseLeave: function() { setHovered(false); }
  },
    React.createElement('div', { className: 'technique-id' }, tech.id),
    React.createElement('div', { className: 'technique-name' }, tech.name),
    React.createElement('div', { className: 'technique-actors' }, actorDots),
    // Tooltip
    hovered && React.createElement('div', { className: 'technique-tooltip' },
      React.createElement('div', { className: 'tooltip-tech-id' }, tech.id),
      React.createElement('div', { className: 'tooltip-tech-name' }, tech.name),
      React.createElement('div', { className: 'tooltip-actors-label' }, 'Observed in:'),
      tech.actors.map(function(aKey) {
        var a = actors[aKey];
        return React.createElement('div', {
          key: aKey,
          className: 'tooltip-actor-row'
        },
          React.createElement('span', {
            className: 'tooltip-actor-dot',
            style: { background: a.color }
          }),
          a.name
        );
      })
    )
  );
}

// ── Tactic Column ─────────────────────────────────────────────
function TacticColumn({ tactic, actors }) {
  return React.createElement('div', { className: 'mitre-tactic-col' },
    // Tactic header
    React.createElement('div', { className: 'mitre-tactic-header' },
      React.createElement('span', { className: 'tactic-header-id' }, tactic.id),
      React.createElement('span', { className: 'tactic-header-name' }, tactic.name)
    ),
    // Technique cells
    tactic.techniques.map(function(tech) {
      return React.createElement(TechniqueCell, {
        key: tech.id + '-' + tactic.id,
        tech: tech,
        actors: actors
      });
    })
  );
}

// ── Main MITRE Section ────────────────────────────────────────
function MitreSection() {
  return React.createElement('section', {
    id: 'mitre',
    className: 'page-section features-bg',
    'aria-labelledby': 'mitre-heading'
  },
    React.createElement('div', { className: 'section-container' },
      // Header
      React.createElement('div', { className: 'reveal' },
        React.createElement('div', { className: 'section-eyebrow' }, 'Framework Coverage'),
        React.createElement('h2', {
          id: 'mitre-heading',
          className: 'section-title'
        }, 'MITRE ATT\u0026CK', React.createElement('br'), 'Cloud Matrix'),
        React.createElement('p', { className: 'section-desc' },
          'Real-world techniques mapped from threat intelligence. Hover over any technique to see which APT groups have been observed using it.'
        )
      ),
      // Legend
      React.createElement('div', { className: 'mitre-legend reveal' },
        React.createElement('span', { className: 'mitre-legend-label' }, 'Threat Actors:'),
        Object.keys(MITRE_DATA.actors).map(function(key) {
          var a = MITRE_DATA.actors[key];
          return React.createElement('span', {
            key: key,
            className: 'mitre-legend-item'
          },
            React.createElement('span', {
              className: 'mitre-legend-dot',
              style: { background: a.color }
            }),
            a.name
          );
        })
      ),
      // Matrix
      React.createElement('div', { className: 'mitre-matrix reveal' },
        MITRE_DATA.tactics.map(function(tactic) {
          return React.createElement(TacticColumn, {
            key: tactic.id,
            tactic: tactic,
            actors: MITRE_DATA.actors
          });
        })
      )
    )
  );
}
