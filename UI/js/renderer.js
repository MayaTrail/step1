/* ══════════════════════════════════════════
   MayaTrail — Shared Renderer Module
   Generates HTML from platform data objects
   ══════════════════════════════════════════ */

(function() {
  'use strict';

  var R = {};

  // ── Severity color helper ──
  function severityColor(sev) {
    switch (sev) {
      case 'CRITICAL': return 'var(--red)';
      case 'HIGH': return 'var(--orange)';
      case 'MEDIUM': return 'var(--text-secondary)';
      case 'LOW': return 'var(--text-muted)';
      default: return 'var(--text-secondary)';
    }
  }

  function tacticClass(tactic) {
    var t = tactic.toLowerCase();
    if (t.indexOf('initial') !== -1) return 'tactic-initial';
    if (t.indexOf('execution') !== -1) return 'tactic-execution';
    if (t.indexOf('persistence') !== -1) return 'tactic-persistence';
    if (t.indexOf('priv') !== -1) return 'tactic-privesc';
    if (t.indexOf('defense') !== -1) return 'tactic-defense';
    if (t.indexOf('lateral') !== -1) return 'tactic-lateral';
    if (t.indexOf('exfil') !== -1) return 'tactic-exfil';
    if (t.indexOf('collection') !== -1) return 'tactic-collection';
    if (t.indexOf('discovery') !== -1) return 'tactic-discovery';
    if (t.indexOf('credential') !== -1) return 'tactic-credential';
    if (t.indexOf('impact') !== -1) return 'tactic-impact';
    return 'tactic-defense';
  }

  var phaseColors = ['var(--red)', 'var(--orange)', '#fbbf24', 'var(--cyan)', 'var(--purple)', 'var(--green)'];

  // ── Escape HTML ──
  function esc(str) {
    var d = document.createElement('div');
    d.textContent = str;
    return d.innerHTML;
  }

  // ══════════════════════════════════
  //  EMULATIONS LIST
  // ══════════════════════════════════
  R.renderEmulationsList = function(platformId, platformLabel) {
    var data = window.MayaTrail.platforms[platformId];
    if (!data || !data.emulations) {
      return '<div class="empty-state"><div class="empty-state-icon">&#128203;</div>' +
             '<div class="empty-state-title">No emulations available</div>' +
             '<div class="empty-state-body">Emulations for ' + esc(platformLabel) + ' are coming soon.</div></div>';
    }
    var emus = data.emulations;
    var html = '';

    // Breadcrumb
    html += '<div class="breadcrumb"><a onclick="showScreen(\'dashboard\')">Home</a><span>/</span> ' + esc(platformLabel) + ' <span>/</span> APT Emulations</div>';

    // Page header
    html += '<div class="page-header"><div>';
    html += '<div class="page-title">' + esc(platformLabel) + ' &middot; APT Emulations</div>';
    html += '<div class="page-subtitle">' + emus.length + ' emulations available &middot; Sorted by threat severity</div>';
    html += '</div><div class="page-actions">';
    html += '<button class="btn btn-secondary" onclick="exportList()">&#11015; Export List</button>';
    html += '<button class="btn btn-run" onclick="showRunModal()">&#9654; Run Custom</button>';
    html += '</div></div>';

    // Filter bar
    var origins = {};
    for (var i = 0; i < emus.length; i++) {
      if (emus[i].originLabel) origins[emus[i].originLabel] = true;
    }
    html += '<div class="filter-bar">';
    html += '<span style="font-family:var(--font-mono);font-size:10px;color:var(--text-muted);letter-spacing:1px">FILTER:</span>';
    html += '<div class="filter-chip active">All</div>';
    for (var k in origins) {
      html += '<div class="filter-chip">' + esc(k) + '-nexus</div>';
    }
    html += '</div>';

    // Emulation cards
    html += '<div class="emulation-list">';
    for (var j = 0; j < emus.length; j++) {
      var em = emus[j];
      html += '<div class="emulation-card" onclick="showEmulationDetail(\'' + platformId + '\',' + j + ')">';
      html += '<div class="emulation-meta">';
      html += '<div class="emulation-title">' + esc(em.name);
      if (em.originLabel) {
        html += ' <span class="threat-origin threat-' + esc(em.origin) + '">' + esc(em.originLabel) + '</span>';
      }
      html += '</div>';
      html += '<div class="emulation-tags">';
      for (var t = 0; t < em.tags.length; t++) {
        html += '<span class="tag">' + esc(em.tags[t]) + '</span>';
      }
      html += '</div></div>';
      html += '<div class="emulation-stats">';
      html += '<div class="emulation-stat-item"><div class="emulation-stat-value" style="color:' + severityColor(em.severity) + '">' + em.techniqueCount + '</div><div class="emulation-stat-label">TECHNIQUES</div></div>';
      html += '<div class="emulation-stat-item"><div class="emulation-stat-value" style="color:' + severityColor(em.severity) + '">' + esc(em.severity) + '</div><div class="emulation-stat-label">SEVERITY</div></div>';
      html += '</div>';
      html += '<div class="emulation-actions">';
      html += '<button class="btn btn-run" onclick="event.stopPropagation(); showRunModal()">&#9654; Run</button>';
      html += '<button class="btn btn-playbook" onclick="event.stopPropagation(); showPlaybook(\'' + platformId + '\',' + j + ')">&#128203; Playbook</button>';
      html += '</div></div>';
    }
    html += '</div>';
    return html;
  };

  // ══════════════════════════════════
  //  EMULATION DETAIL
  // ══════════════════════════════════
  R.renderEmulationDetail = function(platformId, emulationIndex, platformLabel) {
    var data = window.MayaTrail.platforms[platformId];
    if (!data || !data.emulations || !data.emulations[emulationIndex]) return '';
    var em = data.emulations[emulationIndex];
    var html = '';

    // Breadcrumb
    html += '<div class="breadcrumb"><a onclick="showScreen(\'dashboard\')">Home</a><span>/</span>';
    html += '<a onclick="showPlatformEmulations(\'' + platformId + '\')">' + esc(platformLabel) + ' &middot; APT Emulations</a>';
    html += '<span>/</span> ' + esc(em.name) + '</div>';

    // Header
    html += '<div class="page-header"><div>';
    html += '<div class="page-title">' + esc(em.name);
    if (em.originLabel) {
      html += ' <span class="threat-origin threat-' + esc(em.origin) + '" style="font-size:12px;vertical-align:middle;margin-left:8px">' + esc(em.originLabel) + '</span>';
    }
    html += '</div>';
    html += '<div class="page-subtitle" style="margin-top:6px">' + esc(em.aliases || '') + ' &middot; ' + em.techniqueCount + ' MITRE Techniques &middot; ' + esc(platformLabel) + ' Kill Chain</div>';
    html += '</div><div class="page-actions">';
    html += '<button class="btn btn-secondary" onclick="showPlatformEmulations(\'' + platformId + '\')">&#8592; Back</button>';
    html += '<button class="btn btn-playbook" onclick="showPlaybook(\'' + platformId + '\',' + emulationIndex + ')">&#128203; View Playbook</button>';
    html += '<button class="btn btn-run" onclick="showRunModal()">&#9654; Run Emulation</button>';
    html += '</div></div>';

    // Tabs
    html += '<div class="detail-tabs">';
    html += '<div class="detail-tab active" onclick="switchDetailTab(this,\'dtab-path-' + platformId + '-' + emulationIndex + '\')">Attack Path</div>';
    html += '<div class="detail-tab" onclick="switchDetailTab(this,\'dtab-mitre-' + platformId + '-' + emulationIndex + '\')">MITRE Mapping</div>';
    html += '<div class="detail-tab" onclick="switchDetailTab(this,\'dtab-refs-' + platformId + '-' + emulationIndex + '\')">References</div>';
    html += '<div class="detail-tab" onclick="switchDetailTab(this,\'dtab-findings-' + platformId + '-' + emulationIndex + '\')">Past Findings</div>';
    html += '</div>';

    // ── Attack Path Tab ──
    html += '<div class="tab-content active" id="dtab-path-' + platformId + '-' + emulationIndex + '">';
    html += '<div class="detail-grid"><div><div class="section-card"><div class="section-card-title">Kill Chain Visualization</div>';
    html += '<div class="attack-path">';

    if (em.attackPath) {
      for (var p = 0; p < em.attackPath.length; p++) {
        var phase = em.attackPath[p];
        var color = phaseColors[p % phaseColors.length];
        var isLast = (p === em.attackPath.length - 1);
        html += '<div class="attack-phase"><div class="phase-line">';
        html += '<div class="phase-dot" style="background:' + color + '"></div>';
        if (!isLast) html += '<div class="phase-connector"></div>';
        html += '</div><div class="phase-content">';
        html += '<div class="phase-name" style="color:' + color + '">Phase ' + phase.phase + ' &middot; ' + esc(phase.name) + '</div>';
        html += '<div class="technique-chips">';
        for (var tc = 0; tc < phase.techniques.length; tc++) {
          var tech = phase.techniques[tc];
          html += '<div class="technique-chip"><span class="tid">' + esc(tech.id) + '</span> ' + esc(tech.name) + '</div>';
        }
        html += '</div></div></div>';
      }
    }

    html += '</div></div></div>';

    // Summary sidebar
    html += '<div><div class="section-card"><div class="section-card-title">Emulation Summary</div>';
    html += '<div class="detail-meta-row">';
    if (em.name) html += '<div class="detail-meta-item"><div class="detail-meta-label">THREAT ACTOR</div><div class="detail-meta-value">' + esc(em.name.split(' — ')[0]) + '</div></div>';
    if (em.attribution) html += '<div class="detail-meta-item"><div class="detail-meta-label">ATTRIBUTION</div><div class="detail-meta-value" style="color:var(--red)">' + esc(em.attribution) + '</div></div>';
    if (em.activeSince) html += '<div class="detail-meta-item"><div class="detail-meta-label">ACTIVE SINCE</div><div class="detail-meta-value" style="color:var(--text-secondary)">' + esc(em.activeSince) + '</div></div>';
    if (em.targets) html += '<div class="detail-meta-item"><div class="detail-meta-label">TARGETS</div><div class="detail-meta-value" style="font-size:12px;color:var(--text-secondary)">' + esc(em.targets) + '</div></div>';
    if (em.incidents && em.incidents.length) {
      html += '<div class="detail-meta-item"><div class="detail-meta-label">NOTABLE INCIDENTS</div><div class="detail-meta-value mono">' + em.incidents.map(esc).join('<br>') + '</div></div>';
    }
    html += '</div></div></div></div></div>';

    // ── MITRE Tab ──
    html += '<div class="tab-content" id="dtab-mitre-' + platformId + '-' + emulationIndex + '">';
    html += '<div class="section-card"><div class="section-card-title">MITRE ATT&CK Mapping &mdash; ' + esc(platformLabel) + '</div>';
    html += '<table class="mitre-table"><thead><tr><th>Technique ID</th><th>Technique Name</th><th>Tactic</th><th>Platform</th><th>Description</th></tr></thead><tbody>';
    if (em.mitreMappings) {
      for (var m = 0; m < em.mitreMappings.length; m++) {
        var mt = em.mitreMappings[m];
        html += '<tr><td><span class="tid-badge">' + esc(mt.id) + '</span></td>';
        html += '<td>' + esc(mt.name) + '</td>';
        html += '<td><span class="tactic-badge ' + tacticClass(mt.tactic) + '">' + esc(mt.tactic) + '</span></td>';
        html += '<td>' + esc(mt.platform) + '</td>';
        html += '<td style="font-family:var(--font-mono);font-size:11px;color:var(--text-muted)">' + esc(mt.description) + '</td></tr>';
      }
    }
    html += '</tbody></table></div></div>';

    // ── References Tab ──
    html += '<div class="tab-content" id="dtab-refs-' + platformId + '-' + emulationIndex + '">';
    html += '<div class="section-card"><div class="section-card-title">APT Advisories & Intelligence Reports</div>';
    html += '<div class="ref-list">';
    if (em.references) {
      for (var r = 0; r < em.references.length; r++) {
        var ref = em.references[r];
        html += '<div class="ref-item"><div class="ref-icon">' + (ref.icon || '&#128196;') + '</div>';
        html += '<div class="ref-meta"><div class="ref-title">' + esc(ref.title) + '</div>';
        html += '<div class="ref-source">' + esc(ref.source) + '</div></div>';
        html += '<span class="ref-type" style="border-color:' + (ref.color || 'var(--cyan)') + ';color:' + (ref.color || 'var(--cyan)') + '">' + esc(ref.type) + '</span></div>';
      }
    }
    html += '</div></div></div>';

    // ── Findings Tab ──
    html += '<div class="tab-content" id="dtab-findings-' + platformId + '-' + emulationIndex + '">';
    html += '<div class="empty-state"><div class="empty-state-icon">&#128202;</div>';
    html += '<div class="empty-state-title">No previous runs found</div>';
    html += '<div class="empty-state-body">Run this emulation to generate findings and track your security posture over time.<br>Findings will appear here after each execution.</div></div></div>';

    return html;
  };

  // ══════════════════════════════════
  //  PLAYBOOK
  // ══════════════════════════════════
  R.renderPlaybook = function(platformId, emulationIndex, platformLabel) {
    var data = window.MayaTrail.platforms[platformId];
    if (!data || !data.playbooks || !data.playbooks[emulationIndex]) return '';
    var pb = data.playbooks[emulationIndex];
    var emName = (data.emulations && data.emulations[emulationIndex]) ? data.emulations[emulationIndex].name : '';
    var html = '';

    // Breadcrumb
    html += '<div class="breadcrumb"><a onclick="showScreen(\'dashboard\')">Home</a> <span>/</span> ';
    html += '<a onclick="showPlatformEmulations(\'' + platformId + '\')">' + esc(platformLabel) + ' &middot; APT Emulations</a> <span>/</span> ';
    html += '<a onclick="showEmulationDetail(\'' + platformId + '\',' + emulationIndex + ')">' + esc(emName) + '</a> <span>/</span> Playbook</div>';

    // Header
    html += '<div class="page-header"><div>';
    html += '<div class="page-title">&#128203; Incident Response Playbook</div>';
    html += '<div class="page-subtitle">' + esc(emName) + ' &middot; ' + esc(platformLabel) + ' Cloud Environment &middot; Last updated Feb 2025</div>';
    html += '</div><div class="page-actions">';
    html += '<button class="btn btn-secondary" onclick="showEmulationDetail(\'' + platformId + '\',' + emulationIndex + ')">&#8592; Back</button>';
    html += '<button class="btn btn-secondary">&#11015; Export PDF</button>';
    html += '<button class="btn btn-run" onclick="showRunModal()">&#9654; Run Emulation</button>';
    html += '</div></div>';

    // Steps
    html += '<div class="playbook-steps">';
    for (var s = 0; s < pb.steps.length; s++) {
      var step = pb.steps[s];
      html += '<div class="playbook-step">';
      html += '<div class="step-number">' + String(s + 1).padStart(2, '0') + '</div>';
      html += '<div class="step-content">';
      html += '<div class="step-title">' + esc(step.title) + '</div>';
      html += '<div class="step-body">' + esc(step.body) + '</div>';
      if (step.code) {
        html += '<div class="code-block">' + esc(step.code) + '</div>';
      }
      html += '</div></div>';
    }
    html += '</div>';
    return html;
  };

  // ══════════════════════════════════
  //  DETECTIONS
  // ══════════════════════════════════
  R.renderDetections = function(platformId, platformLabel) {
    var data = window.MayaTrail.platforms[platformId];
    if (!data || !data.detections) return '';
    var det = data.detections;
    var html = '';

    // Breadcrumb
    html += '<div class="breadcrumb"><a onclick="showScreen(\'dashboard\')">Home</a> <span>/</span> ' + esc(platformLabel) + ' <span>/</span> Detections</div>';

    // Header
    html += '<div class="page-header"><div>';
    html += '<div class="page-title">' + esc(platformLabel) + ' &middot; Detection Library</div>';
    html += '<div class="page-subtitle">' + (det.ruleCount || 0) + ' rules &middot; ' + (det.formats || 'SIGMA &middot; KQL &middot; YARA') + '</div>';
    html += '</div><div class="page-actions"><button class="btn btn-secondary">&#11015; Export All Rules</button></div></div>';

    // Rules
    if (det.rules) {
      for (var r = 0; r < det.rules.length; r++) {
        var rule = det.rules[r];
        html += '<div class="section-card"><div class="section-card-title">' + esc(rule.title) + '</div>';
        html += '<div class="code-block">' + esc(rule.code) + '</div></div>';
      }
    }
    return html;
  };

  // ══════════════════════════════════
  //  GUARDRAILS
  // ══════════════════════════════════
  R.renderGuardrails = function(platformId, platformLabel) {
    var data = window.MayaTrail.platforms[platformId];
    if (!data || !data.guardrails) return '';
    var gr = data.guardrails;
    var html = '';

    // Breadcrumb
    html += '<div class="breadcrumb"><a onclick="showScreen(\'dashboard\')">Home</a> <span>/</span> ' + esc(platformLabel) + ' <span>/</span> Guardrails</div>';

    // Header
    html += '<div class="page-header"><div>';
    html += '<div class="page-title">' + esc(platformLabel) + ' &middot; Guardrails Configuration</div>';
    html += '<div class="page-subtitle">Define emulation scope, boundaries, and auto-block policies</div>';
    html += '</div><div class="page-actions"><button class="btn btn-run">&#128190; Save Config</button></div></div>';

    // Excluded resources
    html += '<div class="section-card"><div class="section-card-title">Excluded Resources</div>';
    html += '<div style="font-family:var(--font-mono);font-size:12px;color:var(--text-muted);line-height:2">';
    if (gr.excluded) {
      for (var e = 0; e < gr.excluded.length; e++) {
        html += '<div>&#128683; ' + esc(gr.excluded[e]) + '</div>';
      }
    }
    html += '</div></div>';

    // Allowed window
    html += '<div class="section-card"><div class="section-card-title">Allowed Emulation Window</div>';
    html += '<div style="font-family:var(--font-mono);font-size:12px;color:var(--text-muted)">';
    html += esc(gr.schedule || 'Monday – Friday | 02:00 – 06:00 UTC | Auto-pause on incidents');
    html += '</div></div>';

    // Scope limits
    if (gr.scopeLimits) {
      html += '<div class="section-card"><div class="section-card-title">Scope Limits</div>';
      html += '<div style="font-family:var(--font-mono);font-size:12px;color:var(--text-muted);line-height:2">';
      for (var sl = 0; sl < gr.scopeLimits.length; sl++) {
        html += '<div>&#9888;&#65039; ' + esc(gr.scopeLimits[sl]) + '</div>';
      }
      html += '</div></div>';
    }

    return html;
  };

  // ── Dashboard ──
  R.renderDashboard = function() {
    var totalEmulations = 0;
    var totalTechniques = 0;
    var platforms = window.MayaTrail.platforms || {};
    for (var pid in platforms) {
      if (platforms[pid].emulations) {
        totalEmulations += platforms[pid].emulations.length;
        for (var i = 0; i < platforms[pid].emulations.length; i++) {
          totalTechniques += platforms[pid].emulations[i].techniqueCount || 0;
        }
      }
    }

    var html = '<div class="dashboard-hero">';
    html += '<div class="hero-tag">APT EMULATION PLATFORM v2.1</div>';
    html += '<h1>Welcome to MayaTrail</h1>';
    html += '<p>Proactively defend your cloud infrastructure by emulating real-world APT techniques. Test your detections, validate your playbooks, and strengthen your security posture before adversaries do.</p>';
    html += '</div>';

    html += '<div class="stats-row">';
    html += '<div class="stat-card"><div class="stat-value" style="color:var(--orange)">' + totalEmulations + '</div><div class="stat-label">APT Emulations</div></div>';
    html += '<div class="stat-card"><div class="stat-value" style="color:var(--purple)">' + totalTechniques + '</div><div class="stat-label">MITRE Techniques</div></div>';
    html += '<div class="stat-card"><div class="stat-value" style="color:var(--green)">212</div><div class="stat-label">Detection Rules</div></div>';
    html += '<div class="stat-card"><div class="stat-value" style="color:var(--cyan)">5</div><div class="stat-label">Cloud Platforms</div></div>';
    html += '</div>';

    html += '<div class="def-grid">';
    html += '<div class="def-card cyan"><div class="def-card-icon">&#127919;</div><div class="def-card-title">Adversary Emulation</div><div class="def-card-body">Realistic simulation of TTPs used by known threat actors — based on real-world intelligence, MITRE ATT&CK mappings, and live incident data. Not just scanning; full kill-chain execution in a controlled manner.</div></div>';
    html += '<div class="def-card purple"><div class="def-card-icon">&#128203;</div><div class="def-card-title">Playbooks</div><div class="def-card-body">Step-by-step Incident Response guides co-authored with emulation results. Each playbook maps directly to a threat actor\'s known behavior — triage steps, detection logic, containment, and eradication included.</div></div>';
    html += '<div class="def-card green"><div class="def-card-icon">&#128214;</div><div class="def-card-title">Runbooks</div><div class="def-card-body">Operational automation scripts tied to each emulation scenario. Runbooks codify your IR workflows for repeatable, consistent response execution across your SOC team.</div></div>';
    html += '<div class="def-card orange"><div class="def-card-icon">&#128269;</div><div class="def-card-title">Detections</div><div class="def-card-body">SIGMA rules, KQL queries, and YARA signatures generated directly from emulation results. Every emulation run produces exportable detection logic for your SIEM or EDR platform.</div></div>';
    html += '<div class="def-card red"><div class="def-card-icon">&#128737;</div><div class="def-card-title">Guardrails</div><div class="def-card-body">Org-level policies that define emulation scope, restrict blast radius, and prevent unintended impact. Define safe zones, excluded resources, and time windows to run emulations with confidence.</div></div>';
    html += '<div class="def-card" style="border-top:2px solid #fbbf24"><div class="def-card-icon">&#128506;</div><div class="def-card-title">Why Emulation?</div><div class="def-card-body">Adversary emulation bridges the gap between threat intelligence and actual defense validation. Knowing an attack exists ≠ being protected against it. MayaTrail proves your defenses work — or shows you where they don\'t.</div></div>';
    html += '</div>';

    return html;
  };

  window.MayaTrailRenderer = R;
})();
