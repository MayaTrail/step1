/* =====================================================================
   MayaTrail Landing v2.1 - Vault hero + Aurora + Tweaks
   Fixes: seam diamond alignment, phase-snap vault, cursor-linked particles
   ===================================================================== */

const { useEffect, useRef, useState } = React;

/* ---- TWEAK DEFAULTS (host-rewritable) ---- */
const TWEAK_DEFAULTS = /*EDITMODE-BEGIN*/{
  "auroraIntensity": 1,
  "auroraFlavor": "particle",
  "vaultAutoplay": false,
  "accentPalette": ["#6aa8ff", "#ff4b6e"],
  "density": "regular"
}/*EDITMODE-END*/;

function hexA(hex, alpha) {
  if (!hex || hex[0] !== '#') return `rgba(106,168,255,${alpha})`;
  const r = parseInt(hex.slice(1,3),16),
        g = parseInt(hex.slice(3,5),16),
        b = parseInt(hex.slice(5,7),16);
  return `rgba(${r},${g},${b},${alpha})`;
}

/* ===========================================================
   ISO SCENE
   =========================================================== */
function IsoScene({ scale = 1, attackPhase = 'recon', dim = false, accent = '#6aa8ff', hot = '#ff4b6e' }) {
  const tiles = [
    { id: 'IAM USER',   sub: 'sandbox/dev', x: 30,  y: 70,  state: 'cool' },
    { id: 'ROLE admin', sub: 'iam',         x: 170, y: 50,  state: attackPhase === 'idle' ? 'neutral' : 'done' },
    { id: 'LAMBDA',     sub: 'fn:scan',     x: 280, y: 120, state: 'neutral' },
    { id: 'S3 BUCKET',  sub: 'data-lake-x', x: 220, y: 220,
      state: attackPhase === 'contained' ? 'ok' : attackPhase === 'exec' ? 'hot' : 'neutral' },
    { id: 'KMS KEY',    sub: 'alias/prod',  x: 80,  y: 230, state: 'neutral' },
    { id: 'DYNAMODB',   sub: 'tbl:secrets', x: 320, y: 240, state: 'neutral' },
  ];
  const tileColor = (s) => {
    if (s === 'hot')  return { border: hot,    bg: 'rgba(255,75,110,0.10)',  fg: hot,    glow: '0 0 24px rgba(255,75,110,0.24)' };
    if (s === 'cool') return { border: accent, bg: 'rgba(106,168,255,0.10)', fg: accent, glow: 'none' };
    if (s === 'done') return { border: '#6c7385', bg: '#11141c', fg: '#6c7385', glow: 'none' };
    if (s === 'ok')   return { border: '#6fb35f', bg: 'rgba(111,179,95,0.10)', fg: '#6fb35f', glow: '0 0 20px rgba(111,179,95,0.22)' };
    return { border: '#3a4256', bg: '#11141c', fg: '#aab0bf', glow: 'none' };
  };
  const pathStroke =
    attackPhase === 'contained' ? '#6fb35f' :
    attackPhase === 'exec'      ? hot :
    attackPhase === 'recon'     ? accent :
    '#404654';

  return (
    <div style={{
      position: 'absolute', left: '50%', top: '50%',
      width: 420, height: 320,
      transform: `translate(-50%, -50%) scale(${scale}) rotateX(56deg) rotateZ(-42deg)`,
      transformStyle: 'preserve-3d', transformOrigin: '50% 50%',
      opacity: dim ? 0.6 : 1,
      transition: 'transform 0.75s cubic-bezier(.65,.05,.36,1), opacity 0.5s',
    }}>
      <div style={{
        position: 'absolute', inset: 0,
        border: '1px solid var(--rule-2)',
        backgroundImage: `
          linear-gradient(rgba(255,255,255,0.015), rgba(255,255,255,0.015)),
          repeating-linear-gradient(0deg, transparent 0 33px, rgba(255,255,255,0.055) 33px 34px),
          repeating-linear-gradient(90deg, transparent 0 33px, rgba(255,255,255,0.055) 33px 34px)
        `,
      }} />
      <svg viewBox="0 0 420 320"
        style={{ position: 'absolute', inset: 0, width: '100%', height: '100%', transform: 'translateZ(30px)', overflow: 'visible' }}>
        <path d="M 90 120 Q 150 90 230 95" fill="none"
          stroke={attackPhase === 'idle' ? '#404654' : '#6c7385'}
          strokeWidth="2" strokeDasharray="4 4" strokeLinecap="round" />
        {attackPhase !== 'idle' && (
          <path d="M 230 95 Q 260 170 280 250" fill="none"
            stroke={pathStroke} strokeWidth="2"
            strokeDasharray={attackPhase === 'contained' ? '4 4' : '5 7'}
            strokeLinecap="round"
            style={{
              filter: `drop-shadow(0 0 5px ${pathStroke})`,
              animation: (attackPhase === 'exec' || attackPhase === 'recon') ? 'pathDash 1.6s linear infinite' : 'none',
            }} />
        )}
      </svg>
      {tiles.map((t, i) => {
        const c = tileColor(t.state);
        return (
          <div key={i} style={{
            position: 'absolute', left: t.x, top: t.y,
            width: 100, height: 56,
            border: `1px solid ${c.border}`,
            background: c.bg, color: c.fg,
            fontFamily: 'var(--mono)', fontSize: 8.5,
            letterSpacing: '0.1em', textTransform: 'uppercase',
            padding: '7px 9px',
            boxShadow: c.glow,
            transition: 'all 0.5s',
          }}>
            <div>{t.id}</div>
            <div style={{ fontSize: 7, color: '#404654', marginTop: 3, letterSpacing: '0.06em' }}>{t.sub}</div>
            <div style={{ position: 'absolute', inset: 0, background: 'linear-gradient(180deg, rgba(255,255,255,0.05), transparent 60%)', pointerEvents: 'none' }} />
          </div>
        );
      })}
    </div>
  );
}

/* ===========================================================
   AURORA - sweep / blobs / particle
   =========================================================== */
function AuroraSweep({ intensity = 1, accent = '#6aa8ff' }) {
  return (
    <div style={{ position: 'absolute', inset: 0, pointerEvents: 'none', overflow: 'hidden', zIndex: 0 }}>
      <div style={{
        position: 'absolute', inset: 0,
        backgroundImage: `
          linear-gradient(to right, ${hexA(accent, 0.045 * intensity)} 1px, transparent 1px),
          linear-gradient(to bottom, ${hexA(accent, 0.045 * intensity)} 1px, transparent 1px)
        `,
        backgroundSize: '60px 60px',
        maskImage: 'radial-gradient(ellipse 90% 90% at 50% 50%, black 30%, transparent 90%)',
      }} />
      <div style={{
        position: 'absolute', left: 0, right: 0, height: '38%',
        background: `linear-gradient(180deg, transparent 0%, ${hexA(accent, 0.07 * intensity)} 50%, transparent 100%)`,
        animation: 'sweepDown 9s linear infinite',
      }} />
      <div style={{
        position: 'absolute', left: 0, right: 0, top: '60%', height: 1,
        background: `linear-gradient(90deg, transparent, ${hexA(accent, 0.30 * intensity)}, transparent)`,
      }} />
    </div>
  );
}

function AuroraBlobs({ intensity = 1, accent = '#6aa8ff', hot = '#ff4b6e' }) {
  return (
    <div style={{ position: 'absolute', inset: 0, pointerEvents: 'none', overflow: 'hidden', zIndex: 0 }}>
      <div style={{
        position: 'absolute', width: '60%', aspectRatio: '1/1',
        left: '55%', top: '-10%',
        background: `radial-gradient(circle at 50% 50%, ${hexA(accent, 0.14 * intensity)} 0%, transparent 60%)`,
        animation: 'blobDrift1 22s ease-in-out infinite', filter: 'blur(40px)',
      }} />
      <div style={{
        position: 'absolute', width: '50%', aspectRatio: '1/1',
        left: '-10%', bottom: '-15%',
        background: `radial-gradient(circle at 50% 50%, ${hexA(hot, 0.10 * intensity)} 0%, transparent 60%)`,
        animation: 'blobDrift2 28s ease-in-out infinite', filter: 'blur(50px)',
      }} />
    </div>
  );
}

/* Cursor-linked particle field - same flavor as prototype C */
function AuroraParticles({ intensity = 1, accent = '#6aa8ff', hot = '#ff4b6e' }) {
  const canvasRef = useRef(null);
  const mouseRef = useRef({ x: 0.5, y: 0.5, in: false });
  const rafRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const dpr = window.devicePixelRatio || 1;
    let R = canvas.getBoundingClientRect();
    function resize() {
      R = canvas.getBoundingClientRect();
      canvas.width = R.width * dpr;
      canvas.height = R.height * dpr;
      ctx.setTransform(1, 0, 0, 1, 0, 0);
      ctx.scale(dpr, dpr);
    }
    resize();
    window.addEventListener('resize', resize);

    const pts = Array.from({ length: 78 }, () => ({
      x: Math.random(), y: Math.random(),
      vx: (Math.random() - 0.5) * 0.0005,
      vy: (Math.random() - 0.5) * 0.0005,
      hot: Math.random() < 0.16,
    }));

    function onMove(e) {
      R = canvas.getBoundingClientRect();
      mouseRef.current.x = (e.clientX - R.left) / R.width;
      mouseRef.current.y = (e.clientY - R.top) / R.height;
      mouseRef.current.in = true;
    }
    function onLeave() { mouseRef.current.in = false; }
    window.addEventListener('mousemove', onMove);
    window.addEventListener('mouseleave', onLeave);

    function tick() {
      ctx.clearRect(0, 0, R.width, R.height);
      pts.forEach(p => {
        p.x += p.vx; p.y += p.vy;
        if (p.x < 0 || p.x > 1) p.vx *= -1;
        if (p.y < 0 || p.y > 1) p.vy *= -1;
      });
      ctx.lineWidth = 0.5;
      // particle-to-particle links
      for (let i = 0; i < pts.length; i++) {
        for (let j = i + 1; j < pts.length; j++) {
          const dx = (pts[i].x - pts[j].x) * R.width;
          const dy = (pts[i].y - pts[j].y) * R.height;
          const d = Math.sqrt(dx*dx + dy*dy);
          if (d < 120) {
            ctx.strokeStyle = hexA(accent, 0.07 * intensity * (1 - d/120));
            ctx.beginPath();
            ctx.moveTo(pts[i].x * R.width, pts[i].y * R.height);
            ctx.lineTo(pts[j].x * R.width, pts[j].y * R.height);
            ctx.stroke();
          }
        }
      }
      // cursor halo: brighten near-points + draw connecting lines
      const m = mouseRef.current;
      const mx = m.x * R.width, my = m.y * R.height;
      pts.forEach(p => {
        const px = p.x * R.width, py = p.y * R.height;
        let near = false;
        if (m.in) {
          const dx = px - mx, dy = py - my;
          const d = Math.sqrt(dx*dx + dy*dy);
          if (d < 180) {
            near = true;
            ctx.strokeStyle = hexA(p.hot ? hot : accent, 0.18 * intensity * (1 - d/180));
            ctx.beginPath();
            ctx.moveTo(px, py);
            ctx.lineTo(mx, my);
            ctx.stroke();
          }
        }
        ctx.fillStyle = p.hot
          ? hexA(hot, (near ? 0.7 : 0.4) * intensity)
          : hexA(accent, (near ? 0.7 : 0.35) * intensity);
        ctx.beginPath();
        ctx.arc(px, py, near ? 1.8 : 1.1, 0, Math.PI * 2);
        ctx.fill();
      });
      rafRef.current = requestAnimationFrame(tick);
    }
    tick();
    return () => {
      window.removeEventListener('resize', resize);
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('mouseleave', onLeave);
      cancelAnimationFrame(rafRef.current);
    };
  }, [intensity, accent, hot]);

  return <canvas ref={canvasRef} style={{ position: 'absolute', inset: 0, width: '100%', height: '100%', pointerEvents: 'none', zIndex: 0 }} />;
}

/* ===========================================================
   VAULT HERO - phase-snapped, smooth transitions
   =========================================================== */
const PHASES = [
  { key: 'sealed',    label: 'SEALED',                start: 0.00, open: 0.00, color: '#6c7385', chain: 'STANDBY',                  iso: 'idle'  },
  { key: 'pry',       label: 'PRY · STAGE 1',         start: 0.18, open: 0.20, color: '#6c7385', chain: 'INITIALIZING',             iso: 'idle'  },
  { key: 'breached',  label: 'PERIMETER · BREACHED',  start: 0.45, open: 0.62, color: '#f5b454', chain: 'ENUMERATING · T1087.004',  iso: 'recon' },
  { key: 'landed',    label: 'CHAIN LANDED',          start: 0.78, open: 1.00, color: '#ff4b6e', chain: 'EXFIL · T1567.002',        iso: 'exec'  },
];

function VaultHero({ tweaks }) {
  const wrapRef = useRef(null);
  const [progress, setProgress] = useState(0);
  const [autoProgress, setAutoProgress] = useState(0);

  useEffect(() => {
    function onScroll() {
      const wrap = wrapRef.current;
      if (!wrap) return;
      const rect = wrap.getBoundingClientRect();
      const total = wrap.offsetHeight - window.innerHeight;
      const scrolled = -rect.top;
      const p = Math.max(0, Math.min(1, scrolled / total));
      setProgress(p);
    }
    onScroll();
    window.addEventListener('scroll', onScroll, { passive: true });
    return () => window.removeEventListener('scroll', onScroll);
  }, []);

  useEffect(() => {
    if (!tweaks.vaultAutoplay) return;
    let t = 0; let raf;
    function tick() {
      t += 0.0035;
      // cycle through 4 phase centers
      const cyc = (Math.sin(t) + 1) / 2;
      setAutoProgress(cyc);
      raf = requestAnimationFrame(tick);
    }
    tick();
    return () => cancelAnimationFrame(raf);
  }, [tweaks.vaultAutoplay]);

  const liveProgress = tweaks.vaultAutoplay ? autoProgress : progress;

  // Phase snapping: walk phases in order, pick latest whose start ≤ liveProgress
  let phaseIdx = 0;
  for (let i = 0; i < PHASES.length; i++) {
    if (liveProgress >= PHASES[i].start) phaseIdx = i;
  }
  const phase = PHASES[phaseIdx];

  const accent = tweaks.accentPalette?.[0] || '#6aa8ff';
  const hot = tweaks.accentPalette?.[1] || '#ff4b6e';

  return (
    <div ref={wrapRef} style={{ position: 'relative', height: '320vh' }}>
      <div style={{ position: 'sticky', top: 60, height: 'calc(100vh - 60px)', overflow: 'hidden', background: 'var(--bg)' }}>
        {tweaks.auroraFlavor === 'sweep'    && <AuroraSweep    intensity={tweaks.auroraIntensity} accent={accent} />}
        {tweaks.auroraFlavor === 'blobs'    && <AuroraBlobs    intensity={tweaks.auroraIntensity} accent={accent} hot={hot} />}
        {tweaks.auroraFlavor === 'particle' && <AuroraParticles intensity={tweaks.auroraIntensity} accent={accent} hot={hot} />}

        {/* HERO COPY - top */}
        <div style={{
          position: 'absolute', top: 0, left: 0, right: 0,
          padding: 'clamp(24px, 4vh, 40px) 60px 0',
          display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 30,
          zIndex: 6, pointerEvents: 'none',
        }}>
          <div style={{ maxWidth: 'min(540px, 56vw)' }}>
            <span className="tag" style={{ borderColor: phase.color, color: phase.color, transition: 'color 0.4s, border-color 0.4s' }}>
              <span className="dot" style={{ background: phase.color, boxShadow: `0 0 8px ${phase.color}` }} />
              {phase.label}
            </span>
            <h1 className="h1" style={{ fontSize: 'clamp(24px, 2.8vw, 42px)', marginTop: 12, marginBottom: 8 }}>
              Run the attack.<br />
              See <span className="em">which detections</span> fire.
            </h1>
            <p className="lede" style={{ maxWidth: 500, fontSize: 'clamp(14px, 1.15vw, 17px)', marginTop: 14, marginBottom: 0, lineHeight: 1.5, color: 'var(--ink-2)' }}>
              An intentionally-leaky AWS sandbox. A real boto3 attack chain.
              Torn down on one command.
            </p>
          </div>

          <div style={{
            fontFamily: 'var(--mono)', fontSize: 10.5, color: 'var(--ink-3)',
            textTransform: 'uppercase', letterSpacing: '0.16em', textAlign: 'right',
            lineHeight: 1.8, pointerEvents: 'auto',
            display: 'flex', flexDirection: 'column', alignItems: 'flex-end',
          }}>
            <div>SCROLL TO BREACH</div>
            {/* phase ticks */}
            <div style={{ display: 'flex', gap: 4, marginTop: 8 }}>
              {PHASES.map((p, i) => (
                <span key={p.key} style={{
                  width: 26, height: 4,
                  background: i <= phaseIdx ? p.color : 'var(--rule-2)',
                  boxShadow: i === phaseIdx ? `0 0 8px ${p.color}` : 'none',
                  transition: 'background 0.4s, box-shadow 0.4s',
                }} />
              ))}
            </div>
            <div style={{
              marginTop: 8, padding: '3px 8px',
              border: '1px solid var(--rule-2)', display: 'inline-block',
              color: 'var(--ink-2)',
            }}>
              {Math.round(liveProgress * 100).toString().padStart(3, '0')}%
            </div>
          </div>
        </div>

        {/* SCENE STAGE */}
        <div style={{
          position: 'absolute',
          top: 'clamp(220px, 30vh, 280px)',
          left: 60, right: 60,
          bottom: 'clamp(80px, 12vh, 120px)',
          overflow: 'hidden',
          border: '1px solid var(--rule-2)',
          background: 'linear-gradient(180deg, var(--bg-1), var(--bg))',
        }}>
          {/* head */}
          <div style={{
            display: 'flex', alignItems: 'center', gap: 12,
            padding: '10px 16px',
            borderBottom: '1px solid var(--rule)',
            background: 'var(--bg-2)',
            fontFamily: 'var(--mono)', fontSize: 10.5,
            textTransform: 'uppercase', letterSpacing: '0.14em',
            color: 'var(--ink-3)',
          }}>
            <span><b style={{ color: 'var(--ink)' }}>RUN-2F4A</b></span>
            <span style={{ opacity: 0.4 }}>·</span>
            <span>priv-esc-attach-role-policy</span>
            <span style={{ marginLeft: 'auto', color: phase.color, display: 'inline-flex', alignItems: 'center', gap: 6, fontWeight: 600, transition: 'color 0.4s' }}>
              <span style={{ width: 7, height: 7, background: phase.color, borderRadius: '50%', boxShadow: `0 0 8px ${phase.color}`, animation: phaseIdx >= 2 ? 'blip 1.2s ease-out infinite' : 'none', transition: 'background 0.4s' }} />
              {phase.chain}
            </span>
          </div>

          <div style={{ position: 'absolute', inset: '40px 0 40px', overflow: 'hidden' }}>
            <IsoScene
              scale={phaseIdx === 0 ? 0.55 : phaseIdx === 1 ? 0.75 : phaseIdx === 2 ? 0.92 : 1.05}
              attackPhase={phase.iso}
              dim={phaseIdx < 2}
              accent={accent} hot={hot}
            />
            <VaultDoors open={phase.open} accent={accent} hot={hot} sealed={phaseIdx === 0} />
          </div>

          <div style={{
            position: 'absolute', bottom: 0, left: 0, right: 0,
            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
            padding: '10px 16px',
            borderTop: '1px solid var(--rule)',
            background: 'var(--bg-2)',
            fontFamily: 'var(--mono)', fontSize: 10,
            textTransform: 'uppercase', letterSpacing: '0.14em',
            color: 'var(--ink-3)',
          }}>
            <span>READOUT · CloudTrail · {(phase.open * 12.4).toFixed(1)}s</span>
            <div style={{ display: 'flex', gap: 8 }}>
              <span style={{ border: '1px solid var(--rule-2)', color: 'var(--ink-2)', padding: '2px 7px' }}>PULUMI</span>
              <span style={{ border: '1px solid var(--rule-2)', color: 'var(--ink-2)', padding: '2px 7px' }}>BOTO3</span>
              <span style={{ border: `1px solid ${phaseIdx === 3 ? hot : 'var(--rule-2)'}`, color: phaseIdx === 3 ? hot : 'var(--ink-2)', padding: '2px 7px', transition: 'all 0.4s' }}>
                {phaseIdx === 3 ? '⚠ 1 DETECTION GAP' : 'MITRE ATT&CK'}
              </span>
            </div>
          </div>
        </div>

        {/* bottom CTA when fully open */}
        <div style={{
          position: 'absolute', left: 60, right: 60, bottom: 'clamp(14px, 2vh, 28px)',
          display: 'flex', justifyContent: 'space-between', alignItems: 'center',
          opacity: phaseIdx === 3 ? 1 : 0,
          transition: 'opacity 0.6s',
          pointerEvents: phaseIdx === 3 ? 'auto' : 'none',
          zIndex: 7,
        }}>
          <div style={{ display: 'flex', gap: 10 }}>
            <a className="btn" href="MayaTrail Run.html">▶ Watch a live run <span className="arrow">→</span></a>
            <a className="btn outline" href="MayaTrail Scenarios.html">See scenarios</a>
          </div>
          <div style={{
            fontFamily: 'var(--mono)', fontSize: 10.5, color: 'var(--ink-2)',
            textTransform: 'uppercase', letterSpacing: '0.16em',
          }}>
            <span style={{ color: accent }}>cloudtrail.json</span> · <span style={{ color: accent }}>mitre-map.svg</span> · <span style={{ color: accent }}>report.pdf</span>
          </div>
        </div>
      </div>
    </div>
  );
}

/* ===========================================================
   VAULT DOORS - phase-snapped, clean triangle seam diamond
   =========================================================== */
function VaultDoors({ open = 0, accent = '#6aa8ff', hot = '#ff4b6e', sealed = true }) {
  // Smooth CSS transition handles the snap animation
  const trans = 'transform 0.75s cubic-bezier(.65,.05,.36,1), border-color 0.4s, box-shadow 0.4s';
  const shift = open * 100;
  // Diamond half geometry: width 22, height 44 → combined 44×44 vertical diamond at seam
  const DW = 22, DH = 44;

  return (
    <>
      {/* LEFT PANEL */}
      <div style={{
        position: 'absolute', top: 0, bottom: 0, left: 0, width: '50%',
        transform: `translateX(-${shift}%)`,
        willChange: 'transform',
        transition: trans,
        backgroundImage: `
          repeating-linear-gradient(45deg, rgba(255,255,255,0.018) 0 2px, transparent 2px 8px),
          linear-gradient(135deg, #14161e 0%, #0a0b10 100%)
        `,
        borderRight: sealed ? `1px solid ${hot}` : '1px solid var(--rule-3)',
        boxShadow: sealed ? `inset -2px 0 14px ${hexA(hot, 0.18)}` : 'none',
        zIndex: 5,
      }}>
        {Array.from({ length: 9 }).map((_, i) => (
          <div key={i} style={{ position: 'absolute', right: 14, top: 50 + i * 60, width: 6, height: 6, borderRadius: '50%', background: '#1b1f2a', boxShadow: 'inset 0 0 0 1px var(--ink-4)' }} />
        ))}
        <div style={{ position: 'absolute', left: 24, top: 24, fontFamily: 'var(--mono)', fontSize: 9.5, color: 'var(--ink-4)', textTransform: 'uppercase', letterSpacing: '0.18em' }}>SECTOR · 01-A</div>
        <div style={{ position: 'absolute', left: 24, bottom: 24, fontFamily: 'var(--mono)', fontSize: 9.5, color: 'var(--ink-4)', textTransform: 'uppercase', letterSpacing: '0.18em' }}>KEY-LOCK · ACTIVE</div>

        {/* SEAM MARK - LEFT HALF · triangle-web node mark, split at seam */}
        <div style={{ position: 'absolute', top: '50%', right: -2, width: 36, height: 72, transform: 'translateY(-50%)', filter: `drop-shadow(0 0 12px ${hexA(accent, 0.5)})` }}>
          <svg width="36" height="72" viewBox="0 0 60 120">
            <line x1="60" y1="20" x2="22" y2="90" stroke={accent} strokeOpacity="0.5" strokeWidth="3" strokeLinecap="round"/>
            <line x1="60" y1="20" x2="60" y2="64" stroke={accent} strokeOpacity="0.5" strokeWidth="3" strokeLinecap="round"/>
            <line x1="22" y1="90" x2="60" y2="64" stroke={accent} strokeOpacity="0.5" strokeWidth="3" strokeLinecap="round"/>
            <line x1="22" y1="90" x2="98" y2="90" stroke={accent} strokeOpacity="0.5" strokeWidth="3" strokeLinecap="round"/>
            <circle cx="22" cy="90" r="8" fill={accent}/>
            <circle cx="60" cy="64" r="6.5" fill={accent}/>
            <circle cx="60" cy="20" r="8" fill={hot}/>
          </svg>
        </div>
      </div>

      {/* RIGHT PANEL */}
      <div style={{
        position: 'absolute', top: 0, bottom: 0, right: 0, width: '50%',
        transform: `translateX(${shift}%)`,
        willChange: 'transform',
        transition: trans,
        backgroundImage: `
          repeating-linear-gradient(-45deg, rgba(255,255,255,0.018) 0 2px, transparent 2px 8px),
          linear-gradient(-135deg, #14161e 0%, #0a0b10 100%)
        `,
        borderLeft: sealed ? `1px solid ${hot}` : '1px solid var(--rule-3)',
        boxShadow: sealed ? `inset 2px 0 14px ${hexA(hot, 0.18)}` : 'none',
        zIndex: 5,
      }}>
        {Array.from({ length: 9 }).map((_, i) => (
          <div key={i} style={{ position: 'absolute', left: 14, top: 50 + i * 60, width: 6, height: 6, borderRadius: '50%', background: '#1b1f2a', boxShadow: 'inset 0 0 0 1px var(--ink-4)' }} />
        ))}
        <div style={{ position: 'absolute', right: 24, top: 24, fontFamily: 'var(--mono)', fontSize: 9.5, color: 'var(--ink-4)', textTransform: 'uppercase', letterSpacing: '0.18em' }}>SECTOR · 01-B</div>
        <div style={{ position: 'absolute', right: 24, bottom: 24, fontFamily: 'var(--mono)', fontSize: 9.5, color: 'var(--ink-4)', textTransform: 'uppercase', letterSpacing: '0.18em' }}>SIGNAL · NOMINAL</div>

        {/* SEAM MARK - RIGHT HALF · triangle-web node mark, split at seam */}
        <div style={{ position: 'absolute', top: '50%', left: -2, width: 36, height: 72, transform: 'translateY(-50%)', filter: `drop-shadow(0 0 12px ${hexA(accent, 0.5)})` }}>
          <svg width="36" height="72" viewBox="60 0 60 120">
            <line x1="60" y1="20" x2="98" y2="90" stroke={accent} strokeOpacity="0.5" strokeWidth="3" strokeLinecap="round"/>
            <line x1="60" y1="20" x2="60" y2="64" stroke={accent} strokeOpacity="0.5" strokeWidth="3" strokeLinecap="round"/>
            <line x1="98" y1="90" x2="60" y2="64" stroke={accent} strokeOpacity="0.5" strokeWidth="3" strokeLinecap="round"/>
            <line x1="22" y1="90" x2="98" y2="90" stroke={accent} strokeOpacity="0.5" strokeWidth="3" strokeLinecap="round"/>
            <circle cx="98" cy="90" r="8" fill={accent}/>
            <circle cx="60" cy="64" r="6.5" fill={accent}/>
            <circle cx="60" cy="20" r="8" fill={hot}/>
          </svg>
        </div>
      </div>

      {/* central glow band when partly open (always behind doors) */}
      {open > 0 && open < 0.98 && (
        <div style={{
          position: 'absolute', top: 0, bottom: 0, left: '50%',
          width: 8 + open * 220,
          transform: 'translateX(-50%)',
          background: `linear-gradient(90deg, transparent, ${hexA(accent, 0.32)}, transparent)`,
          filter: 'blur(10px)',
          pointerEvents: 'none', zIndex: 4,
          opacity: 1 - open * 0.35,
          transition: 'width 0.75s cubic-bezier(.65,.05,.36,1), opacity 0.75s',
        }} />
      )}
    </>
  );
}

/* ===========================================================
   TWEAKS PANEL
   =========================================================== */
const {
  TweaksPanel, useTweaks,
  TweakSection, TweakSlider, TweakToggle, TweakRadio, TweakSelect, TweakColor,
} = window;

function MTTweaks({ tweaks, setTweak }) {
  return (
    <TweaksPanel>
      <TweakSection label="Aurora" />
      <TweakSelect
        label="Flavor"
        value={tweaks.auroraFlavor}
        options={[
          { value: 'particle', label: 'Particle field (cursor-linked)' },
          { value: 'sweep',    label: 'Signal sweep' },
          { value: 'blobs',    label: 'Drifting blobs' },
          { value: 'none',     label: 'Off' },
        ]}
        onChange={(v) => setTweak('auroraFlavor', v)}
      />
      <TweakSlider
        label="Intensity" value={tweaks.auroraIntensity}
        min={0} max={2} step={0.05}
        onChange={(v) => setTweak('auroraIntensity', v)}
      />

      <TweakSection label="Hero" />
      <TweakToggle
        label="Vault autoplay (loop)"
        value={tweaks.vaultAutoplay}
        onChange={(v) => setTweak('vaultAutoplay', v)}
      />

      <TweakSection label="Palette" />
      <TweakColor
        label="Accent · Hot"
        value={tweaks.accentPalette}
        options={[
          ['#6aa8ff', '#ff4b6e'],
          ['#7ee0c8', '#ff4b6e'],
          ['#b58cff', '#ff4b6e'],
          ['#f5b454', '#ff4b6e'],
          ['#6aa8ff', '#ffc049'],
        ]}
        onChange={(v) => setTweak('accentPalette', v)}
      />

      <TweakSection label="Density" />
      <TweakRadio
        label="Page density"
        value={tweaks.density}
        options={['compact', 'regular', 'roomy']}
        onChange={(v) => setTweak('density', v)}
      />
    </TweaksPanel>
  );
}

/* ===========================================================
   APP
   =========================================================== */
function VaultHeroApp() {
  const [t, setTweak] = useTweaks(TWEAK_DEFAULTS);

  useEffect(() => {
    const [accent, hot] = t.accentPalette || ['#6aa8ff', '#ff4b6e'];
    const root = document.documentElement;
    root.style.setProperty('--cool', accent);
    root.style.setProperty('--cool-dim', hexA(accent, 0.18));
    root.style.setProperty('--hot', hot);
    root.style.setProperty('--hot-dim', hexA(hot, 0.22));
    const dens = t.density === 'compact' ? 0.85 : t.density === 'roomy' ? 1.15 : 1;
    root.style.setProperty('--density', dens);
  }, [t.accentPalette, t.density]);

  return (
    <>
      <VaultHero tweaks={t} />
      <MTTweaks tweaks={t} setTweak={setTweak} />
    </>
  );
}

Object.assign(window, { VaultHeroApp });
