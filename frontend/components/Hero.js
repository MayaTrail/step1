/* Hero Section — Split grid layout with viz-panel + canvas particle animation */

var useState = React.useState;
var useEffect = React.useEffect;
var useRef = React.useRef;
var useCallback = React.useCallback;

// ── APT group names & safe labels ─────────────────────────────
var APT_NAMES = [
  'APT29 \u2014 CozyBear', 'APT28 \u2014 FancyBear', 'APT41 \u2014 WickedPanda',
  'Lazarus Group', 'APT10 \u2014 MenuPass', 'Sandworm', 'Turla',
  'APT33 \u2014 Elfin', 'Kimsuky', 'Volt Typhoon', 'APT38',
  'Scattered Spider', 'BlackCat/ALPHV', 'LockBit', 'CL0P'
];
var SAFE_LABELS = [
  'GET /api/health', 'POST /auth/login', 'GET /dashboard',
  'PUT /user/settings', 'GET /api/v2/data', 'POST /webhook',
  'GET /metrics', 'OPTIONS /cors', 'GET /status', 'POST /upload'
];

// ── Particle class for canvas ─────────────────────────────────
function createParticle(w, h, isSafe) {
  var x = -10;
  var y = 40 + Math.random() * (h - 80);
  var targetX = w - 120;
  var targetY = h / 2 + (Math.random() - 0.5) * 100;
  var speed = 0.8 + Math.random() * 1.5;
  var size = isSafe ? 2.5 : 3;
  var opacity = 0.6 + Math.random() * 0.4;
  var label = isSafe
    ? SAFE_LABELS[Math.floor(Math.random() * SAFE_LABELS.length)]
    : APT_NAMES[Math.floor(Math.random() * APT_NAMES.length)];
  var showLabel = Math.random() > 0.6;
  var wobble = Math.random() * Math.PI * 2;
  var wobbleAmp = isSafe ? 0.3 : 1.5;

  return {
    x: x, y: y, targetX: targetX, targetY: targetY,
    speed: speed, size: size, opacity: opacity,
    label: label, showLabel: showLabel,
    wobble: wobble, wobbleAmp: wobbleAmp,
    safe: isSafe, alive: true,
    trail: []
  };
}

function updateParticle(p) {
  var dx = p.targetX - p.x;
  var dy = p.targetY - p.y;
  var dist = Math.sqrt(dx * dx + dy * dy);
  if (dist < 5) { p.alive = false; return; }
  p.wobble += 0.05;
  var wobbleOffset = Math.sin(p.wobble) * p.wobbleAmp;
  p.x += (dx / dist) * p.speed;
  p.y += (dy / dist) * p.speed * 0.3 + wobbleOffset;
  p.trail.push({ x: p.x, y: p.y });
  if (p.trail.length > 20) p.trail.shift();
}

function drawParticle(ctx, p, w) {
  // Trail
  if (p.trail.length > 1) {
    ctx.beginPath();
    ctx.moveTo(p.trail[0].x, p.trail[0].y);
    for (var i = 1; i < p.trail.length; i++) {
      ctx.lineTo(p.trail[i].x, p.trail[i].y);
    }
    ctx.strokeStyle = p.safe
      ? 'rgba(0, 230, 118, ' + (p.opacity * 0.15) + ')'
      : 'rgba(255, 34, 68, ' + (p.opacity * 0.2) + ')';
    ctx.lineWidth = 1;
    ctx.stroke();
  }
  // Glow
  var gradient = ctx.createRadialGradient(p.x, p.y, 0, p.x, p.y, p.size * 6);
  gradient.addColorStop(0, p.safe
    ? 'rgba(0, 230, 118, ' + (p.opacity * 0.4) + ')'
    : 'rgba(255, 34, 68, ' + (p.opacity * 0.5) + ')');
  gradient.addColorStop(1, 'transparent');
  ctx.fillStyle = gradient;
  ctx.fillRect(p.x - p.size * 6, p.y - p.size * 6, p.size * 12, p.size * 12);
  // Dot
  ctx.beginPath();
  ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
  ctx.fillStyle = p.safe
    ? 'rgba(0, 230, 118, ' + p.opacity + ')'
    : 'rgba(255, 34, 68, ' + p.opacity + ')';
  ctx.fill();
  // Label
  if (p.showLabel && p.x > 30 && p.x < w - 160) {
    ctx.font = '500 9px JetBrains Mono, monospace';
    ctx.fillStyle = p.safe
      ? 'rgba(0, 230, 118, ' + (p.opacity * 0.6) + ')'
      : 'rgba(255, 34, 68, ' + (p.opacity * 0.5) + ')';
    ctx.fillText(p.label, p.x + 8, p.y + 3);
  }
}

// ── Traffic Canvas Component ──────────────────────────────────
function TrafficCanvas({ isProtected }) {
  var canvasRef = useRef(null);
  var particlesRef = useRef([]);
  var animRef = useRef(null);
  var protRef = useRef(isProtected);
  var prefersReducedMotion = useRef(
    typeof window !== 'undefined' && window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches
  );

  useEffect(function() { protRef.current = isProtected; }, [isProtected]);

  useEffect(function() {
    if (prefersReducedMotion.current) return;
    var canvas = canvasRef.current;
    if (!canvas) return;
    var ctx = canvas.getContext('2d');

    function resizeCanvas() {
      canvas.width = canvas.offsetWidth * 2;
      canvas.height = canvas.offsetHeight * 2;
      ctx.scale(2, 2);
    }
    resizeCanvas();
    window.addEventListener('resize', resizeCanvas);

    function animate() {
      var w = canvas.offsetWidth;
      var h = canvas.offsetHeight;
      ctx.clearRect(0, 0, w, h);

      // Subtle grid
      ctx.strokeStyle = 'rgba(255,255,255,0.015)';
      ctx.lineWidth = 0.5;
      for (var x = 0; x < w; x += 40) {
        ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, h); ctx.stroke();
      }
      for (var y = 0; y < h; y += 40) {
        ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke();
      }

      // Target zone glow
      var grd = ctx.createRadialGradient(w - 80, h / 2, 10, w - 80, h / 2, 80);
      grd.addColorStop(0, protRef.current ? 'rgba(0,230,118,0.06)' : 'rgba(255,34,68,0.08)');
      grd.addColorStop(1, 'transparent');
      ctx.fillStyle = grd;
      ctx.fillRect(w - 160, h / 2 - 80, 160, 160);

      particlesRef.current.forEach(function(p) {
        updateParticle(p);
        drawParticle(ctx, p, w);
      });

      particlesRef.current = particlesRef.current.filter(function(p) { return p.alive; });

      if (Math.random() > 0.85) {
        particlesRef.current.push(createParticle(w, h, protRef.current));
      }

      animRef.current = requestAnimationFrame(animate);
    }

    animRef.current = requestAnimationFrame(animate);

    return function() {
      cancelAnimationFrame(animRef.current);
      window.removeEventListener('resize', resizeCanvas);
      particlesRef.current = [];
    };
  }, []);

  return React.createElement('canvas', {
    ref: canvasRef,
    style: { width: '100%', height: '100%' },
    'aria-hidden': 'true'
  });
}

// ── Hero Section ──────────────────────────────────────────────
function HeroSection({ isProtected, onToggle }) {
  var threatCountRef = useRef(null);
  var countAnimRef = useRef(null);

  useEffect(function() {
    var el = threatCountRef.current;
    if (!el) return;
    if (countAnimRef.current) clearInterval(countAnimRef.current);

    if (isProtected) {
      var count = 47;
      countAnimRef.current = setInterval(function() {
        count--;
        el.textContent = 'THREATS: ' + count;
        if (count <= 0) {
          clearInterval(countAnimRef.current);
          el.textContent = 'THREATS: 0 \u2713';
        }
      }, 30);
    } else {
      var c = 0;
      countAnimRef.current = setInterval(function() {
        c += Math.ceil(Math.random() * 3);
        if (c > 47) c = 47;
        el.textContent = 'THREATS: ' + c;
        if (c >= 47) clearInterval(countAnimRef.current);
      }, 40);
    }

    return function() { if (countAnimRef.current) clearInterval(countAnimRef.current); };
  }, [isProtected]);

  return React.createElement('section', {
    className: 'hero-section',
    id: 'hero',
    'aria-label': 'Hero section'
  },
    // Grid bg
    React.createElement('div', { className: 'hero-grid-bg', 'aria-hidden': 'true' }),
    // Content grid
    React.createElement('div', { className: 'hero-content-grid' },
      // LEFT: text
      React.createElement('div', null,
        // Badge
        React.createElement('div', { className: 'hero-badge' + (isProtected ? ' safe' : '') },
          React.createElement('div', { className: 'badge-dot' }),
          React.createElement('span', null, isProtected
            ? 'MAYATRAIL ACTIVE \u2014 ENVIRONMENT PROTECTED'
            : 'THREATS DETECTED IN YOUR ENVIRONMENT'
          )
        ),
        // Title
        React.createElement('h1', { className: 'hero-title' },
          React.createElement('span', null, 'Your AWS Cloud'),
          React.createElement('br'),
          React.createElement('span', {
            className: 'hero-title-highlight' + (isProtected ? ' safe' : '')
          }, isProtected ? 'Protected.' : 'Under Siege.')
        ),
        // Subtitle
        React.createElement('p', { className: 'hero-subtitle' },
          isProtected
            ? 'MayaTrail is actively emulating adversary techniques and generating detection rules, IR playbooks, and guardrails \u2014 transforming threats into actionable defense.'
            : 'APT groups are actively targeting cloud infrastructure. MayaTrail emulates real-world adversary techniques in your AWS environment \u2014 so your team can detect, respond, and block threats before they cause damage.'
        ),
        // Actions
        React.createElement('div', { className: 'hero-actions' },
          React.createElement('a', {
            href: '#contact',
            className: 'btn-primary-main' + (isProtected ? ' safe' : '')
          }, 'Start Emulation'),
          React.createElement('a', {
            href: '#features',
            className: 'btn-secondary-main'
          }, 'See Capabilities \u2192')
        )
      ),
      // RIGHT: viz panel
      React.createElement('div', null,
        React.createElement('div', { className: 'viz-panel' },
          // Viz header
          React.createElement('div', { className: 'viz-header' },
            React.createElement('div', null,
              React.createElement('div', { className: 'viz-label' }, 'Live Environment Monitor'),
              React.createElement('div', { className: 'viz-title' },
                React.createElement('span', {
                  className: 'viz-cloud-name' + (isProtected ? ' safe' : '')
                }, 'AWS Cloud'),
                ' \u2014 Traffic Flow'
              )
            ),
            // Toggle
            React.createElement('div', { className: 'toggle-area' },
              React.createElement('span', { className: 'toggle-label-text' },
                isProtected ? 'MayaTrail ON' : 'MayaTrail OFF'
              ),
              React.createElement('label', { className: 'toggle-switch' },
                React.createElement('input', {
                  type: 'checkbox',
                  checked: isProtected,
                  onChange: onToggle,
                  'aria-label': 'Toggle MayaTrail protection'
                }),
                React.createElement('span', { className: 'toggle-slider' })
              )
            )
          ),
          // Canvas
          React.createElement('div', { className: 'traffic-canvas-wrap' },
            React.createElement(TrafficCanvas, { isProtected: isProtected }),
            React.createElement('div', { className: 'cloud-icon-overlay' },
              React.createElement('svg', { viewBox: '0 0 64 64', fill: 'none' },
                React.createElement('path', {
                  d: 'M52 32c0-8.8-7.2-16-16-16-6.2 0-11.6 3.6-14.2 8.8C14.6 25.4 8 32.4 8 40.8c0 8 6.4 14.4 14.4 14.4h28c7.2 0 13.6-5.6 13.6-12.8 0-6-4-11.2-10-12.4 0 0-2-2-2 2z'
                })
              ),
              React.createElement('span', { className: 'cloud-text' }, 'Your Cloud')
            )
          ),
          // Status bar
          React.createElement('div', { className: 'status-bar' },
            React.createElement('div', { className: 'status-item' },
              React.createElement('div', { className: 'status-dot' + (isProtected ? ' safe' : '') }),
              React.createElement('span', null, isProtected ? 'Safe Traffic Only' : 'APT Traffic Detected')
            ),
            React.createElement('div', { className: 'status-item' },
              React.createElement('span', {
                ref: threatCountRef,
                className: 'threat-counter' + (isProtected ? ' safe' : '')
              }, 'THREATS: 47')
            ),
            React.createElement('div', { className: 'status-item' },
              React.createElement('div', { className: 'status-dot' + (isProtected ? ' safe' : '') }),
              React.createElement('span', null, isProtected ? 'Guardrails Active' : 'Guardrails Inactive')
            )
          ),
          // Platforms strip
          React.createElement('div', { className: 'platforms-strip' },
            '\uD83D\uDD1C Expanding to: ',
            React.createElement('span', { className: 'platform-name' }, 'Azure'),
            ' \u00B7 ',
            React.createElement('span', { className: 'platform-name' }, 'GCP'),
            ' \u00B7 ',
            React.createElement('span', { className: 'platform-name' }, 'Kubernetes'),
            React.createElement('span', { className: 'coming-soon-tag' }, 'Coming Soon')
          )
        )
      )
    )
  );
}
