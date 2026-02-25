/* ══════════════════════════════════════════
   MayaTrail — Core Application Module
   Navigation, search, modals, theme toggle
   ══════════════════════════════════════════ */

(function() {
  'use strict';

  // ── Platform registry ──
  var PLATFORMS = {
    aws:   { id: 'aws',   label: 'AWS',        icon: '&#9729;&#65039;', badge: '12' },
    ai:    { id: 'ai',    label: 'AI',         icon: '&#129302;',      badge: '4'  },
    gcp:   { id: 'gcp',   label: 'GCP',        icon: '&#128309;',      badge: '8'  },
    azure: { id: 'azure', label: 'Azure',      icon: '&#128311;',      badge: '9'  },
    k8s:   { id: 'k8s',   label: 'Kubernetes', icon: '&#9881;&#65039;', badge: '6'  }
  };

  var currentPlatform = 'aws';
  var currentSection = 'dashboard';
  var currentEmulationIndex = 0;

  // ── Init on DOM ready ──
  window.addEventListener('DOMContentLoaded', function() {
    // Auth check
    if (window.MayaTrailAuth && !window.MayaTrailAuth.getSession()) {
      window.location.href = 'login.html';
      return;
    }

    // Set user info
    var session = window.MayaTrailAuth ? window.MayaTrailAuth.getSession() : null;
    if (session) {
      var avatarEl = document.getElementById('userAvatar');
      var nameEl = document.getElementById('userName');
      var ddName = document.getElementById('ddName');
      var ddEmail = document.getElementById('ddEmail');
      if (avatarEl) avatarEl.textContent = session.initials || 'AP';
      if (nameEl) nameEl.textContent = (session.name || 'User').split(' ')[0] + ' ' + ((session.name || '').split(' ')[1] || '').charAt(0) + '.';
      if (ddName) ddName.textContent = session.name || 'User';
      if (ddEmail) ddEmail.textContent = session.username || '';
    }

    // Update badge counts from actual data
    for (var pid in PLATFORMS) {
      var pdata = window.MayaTrail && window.MayaTrail.platforms && window.MayaTrail.platforms[pid];
      if (pdata && pdata.emulations) {
        PLATFORMS[pid].badge = String(pdata.emulations.length);
        var badgeEl = document.getElementById('badge-' + pid);
        if (badgeEl) badgeEl.textContent = pdata.emulations.length;
      }
    }

    // Show dashboard
    showScreen('dashboard');
  });

  // ══════════════════════════════════
  //  NAVIGATION
  // ══════════════════════════════════
  window.showScreen = function(id) {
    var contentEl = document.getElementById('mainContent');
    if (!contentEl) return;

    currentSection = id;
    var R = window.MayaTrailRenderer;
    var pLabel = PLATFORMS[currentPlatform] ? PLATFORMS[currentPlatform].label : 'AWS';
    var html = '';

    switch (id) {
      case 'dashboard':
        html = R.renderDashboard();
        break;
      case 'emulations':
        html = R.renderEmulationsList(currentPlatform, pLabel);
        break;
      case 'detail':
        html = R.renderEmulationDetail(currentPlatform, currentEmulationIndex, pLabel);
        break;
      case 'playbook':
        html = R.renderPlaybook(currentPlatform, currentEmulationIndex, pLabel);
        break;
      case 'detections':
        html = R.renderDetections(currentPlatform, pLabel);
        break;
      case 'guardrails':
        html = R.renderGuardrails(currentPlatform, pLabel);
        break;
      default:
        html = R.renderDashboard();
    }

    contentEl.innerHTML = html;
    contentEl.scrollTop = 0;

    // Update sidebar active state
    updateSidebarState(id);
  };

  window.showPlatformEmulations = function(platformId) {
    currentPlatform = platformId;
    expandPlatformSidebar(platformId);
    showScreen('emulations');
  };

  window.showEmulationDetail = function(platformId, index) {
    currentPlatform = platformId;
    currentEmulationIndex = index;
    showScreen('detail');
  };

  window.showPlaybook = function(platformId, index) {
    currentPlatform = platformId;
    currentEmulationIndex = index;
    showScreen('playbook');
  };

  function updateSidebarState(section) {
    document.querySelectorAll('.sub-item').forEach(function(item) {
      item.classList.remove('active');
    });

    var container = document.getElementById(currentPlatform + '-sub');
    if (!container) return;
    var items = container.querySelectorAll('.sub-item');

    if (section === 'emulations' || section === 'detail') {
      if (items[0]) items[0].classList.add('active');
    } else if (section === 'playbook') {
      if (items[1]) items[1].classList.add('active');
    } else if (section === 'detections') {
      if (items[2]) items[2].classList.add('active');
    } else if (section === 'guardrails') {
      if (items[3]) items[3].classList.add('active');
    }
  }

  // ── Platform toggle ──
  window.togglePlatform = function(name) {
    var sub = document.getElementById(name + '-sub');
    var toggle = document.getElementById(name + '-toggle');
    var isOpen = sub && sub.classList.contains('open');

    // Close all
    document.querySelectorAll('.sub-items').forEach(function(s) { s.classList.remove('open'); });
    document.querySelectorAll('.platform-item').forEach(function(i) { i.classList.remove('active'); });
    document.querySelectorAll('.platform-chevron').forEach(function(c) { c.style.transform = ''; });

    if (!isOpen && sub && toggle) {
      sub.classList.add('open');
      toggle.classList.add('active');
      var chevron = document.getElementById(name + '-chevron');
      if (chevron) chevron.style.transform = 'rotate(90deg)';
      currentPlatform = name;
    }
  };

  function expandPlatformSidebar(name) {
    document.querySelectorAll('.sub-items').forEach(function(s) { s.classList.remove('open'); });
    document.querySelectorAll('.platform-item').forEach(function(i) { i.classList.remove('active'); });
    document.querySelectorAll('.platform-chevron').forEach(function(c) { c.style.transform = ''; });

    var sub = document.getElementById(name + '-sub');
    var toggle = document.getElementById(name + '-toggle');
    if (sub) sub.classList.add('open');
    if (toggle) toggle.classList.add('active');
    var chevron = document.getElementById(name + '-chevron');
    if (chevron) chevron.style.transform = 'rotate(90deg)';
  }

  // ── Sidebar sub-item click handler ──
  window.sidebarNavigate = function(platformId, section) {
    currentPlatform = platformId;
    expandPlatformSidebar(platformId);
    showScreen(section);
  };

  // ── Detail tab switching ──
  window.switchDetailTab = function(el, tabId) {
    var screen = el.closest('#mainContent') || document;
    screen.querySelectorAll('.detail-tab').forEach(function(t) { t.classList.remove('active'); });
    screen.querySelectorAll('.tab-content').forEach(function(t) { t.classList.remove('active'); });
    el.classList.add('active');
    var tab = document.getElementById(tabId);
    if (tab) tab.classList.add('active');
  };

  // ══════════════════════════════════
  //  SEARCH
  // ══════════════════════════════════
  window.openSearch = function() {
    document.getElementById('searchOverlay').classList.add('open');
    setTimeout(function() {
      var input = document.getElementById('searchInput');
      if (input) { input.value = ''; input.focus(); }
    }, 100);
    populateSearchResults('');
  };

  window.closeSearch = function() {
    document.getElementById('searchOverlay').classList.remove('open');
  };

  window.filterSearch = function(val) {
    populateSearchResults(val.toLowerCase().trim());
  };

  function populateSearchResults(query) {
    var resultsEl = document.getElementById('searchResults');
    if (!resultsEl) return;

    var items = [];
    var platforms = window.MayaTrail ? window.MayaTrail.platforms : {};

    for (var pid in platforms) {
      var pdata = platforms[pid];
      var pLabel = PLATFORMS[pid] ? PLATFORMS[pid].label : pid;
      if (pdata.emulations) {
        for (var i = 0; i < pdata.emulations.length; i++) {
          var em = pdata.emulations[i];
          items.push({
            icon: '&#127919;',
            title: em.name,
            sub: pLabel + ' &middot; ' + em.techniqueCount + ' techniques' + (em.originLabel ? ' &middot; ' + em.originLabel + '-nexus' : ''),
            category: 'Emulation',
            action: 'showEmulationDetail(\'' + pid + '\',' + i + '); closeSearch()'
          });
        }
      }
    }

    // Filter
    if (query) {
      items = items.filter(function(item) {
        return item.title.toLowerCase().indexOf(query) !== -1 ||
               item.sub.toLowerCase().indexOf(query) !== -1;
      });
    }

    // Limit to 10
    items = items.slice(0, 10);

    var html = '';
    for (var j = 0; j < items.length; j++) {
      var it = items[j];
      html += '<div class="search-result-item" onclick="' + it.action + '">';
      html += '<div class="search-result-icon">' + it.icon + '</div>';
      html += '<div class="search-result-text"><div class="search-result-title">' + it.title + '</div>';
      html += '<div class="search-result-sub">' + it.sub + '</div></div>';
      html += '<span class="search-result-category">' + it.category + '</span></div>';
    }

    if (items.length === 0) {
      html = '<div style="padding:20px;text-align:center;font-family:var(--font-mono);font-size:12px;color:var(--text-muted)">No results found</div>';
    }

    resultsEl.innerHTML = html;
  }

  // ══════════════════════════════════
  //  MODALS & DROPDOWNS
  // ══════════════════════════════════
  window.showRunModal = function() {
    document.getElementById('runModal').classList.add('open');
  };

  window.closeRunModal = function() {
    document.getElementById('runModal').classList.remove('open');
  };

  window.launchEmulation = function() {
    closeRunModal();
    showToast('Emulation launched — ' + (PLATFORMS[currentPlatform] ? PLATFORMS[currentPlatform].label : '') + ' environment');
  };

  window.exportList = function() {
    showToast('Export started. Download will begin shortly.');
  };

  window.toggleDropdown = function() {
    document.getElementById('accountDropdown').classList.toggle('open');
  };

  window.closeDropdown = function() {
    document.getElementById('accountDropdown').classList.remove('open');
  };

  window.handleLogout = function() {
    closeDropdown();
    if (window.MayaTrailAuth) {
      window.MayaTrailAuth.logout();
    }
  };

  window.showToast = function(msg) {
    var toast = document.getElementById('toast');
    var toastMsg = document.getElementById('toastMsg');
    if (toastMsg) toastMsg.textContent = msg;
    if (toast) {
      toast.classList.add('show');
      setTimeout(function() { toast.classList.remove('show'); }, 3500);
    }
  };

  // ── Theme toggle ──
  var THEME_KEY = 'mayatrail_theme';

  function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    var btn = document.querySelector('.theme-toggle');
    if (btn) {
      btn.innerHTML = theme === 'dark' ? '&#9728;&#65039; Light' : '&#9789; Dark';
    }
  }

  function getStoredTheme() {
    return localStorage.getItem(THEME_KEY) || 'dark';
  }

  // Apply theme on load
  applyTheme(getStoredTheme());

  window.toggleTheme = function() {
    var current = getStoredTheme();
    var next = current === 'dark' ? 'light' : 'dark';
    localStorage.setItem(THEME_KEY, next);
    applyTheme(next);
  };

  // ── Keyboard shortcuts ──
  document.addEventListener('keydown', function(e) {
    if (e.key === '/' && !e.target.matches('input, select, textarea')) {
      e.preventDefault();
      openSearch();
    }
    if (e.key === 'Escape') {
      closeSearch();
      closeDropdown();
      closeRunModal();
    }
  });

  document.addEventListener('click', function(e) {
    if (!e.target.closest('.account-btn') && !e.target.closest('.dropdown-menu')) {
      closeDropdown();
    }
  });

})();
