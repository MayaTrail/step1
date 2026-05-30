/* =====================================================================
   MayaTrail - Run v3 (calm + click-to-inspect)
   Based on v1 story-card narrative, but progressive disclosure:
   - steps collapsed by default
   - click any step → that step's story expands inline
   - no DETECTION FEED bombardment
   - credential flow + cloudtrail tail compact, collapsible
   ===================================================================== */

const { useEffect, useRef, useState, useMemo } = React;

const RUN = JSON.parse(document.getElementById('run-data').textContent);
const NARRATIVES = RUN.narratives || {};

/* ---- helpers ---- */
function hexA(hex, a) {
  if (!hex || hex[0] !== '#') return `rgba(106,168,255,${a})`;
  const r = parseInt(hex.slice(1,3),16), g = parseInt(hex.slice(3,5),16), b = parseInt(hex.slice(5,7),16);
  return `rgba(${r},${g},${b},${a})`;
}
function fmtTime(ms) {
  const s = Math.floor(ms / 1000);
  const m = Math.floor(s / 60);
  return `${String(m).padStart(2,'0')}:${String(s%60).padStart(2,'0')}`;
}
function fmtMoney(n) {
  if (n < 0.01) return `$${n.toFixed(4)}`;
  if (n < 1)    return `$${n.toFixed(3)}`;
  return `$${n.toFixed(2)}`;
}
function shortTactic(t) {
  return ({
    'Resource Development': 'RES DEV', 'Execution': 'EXEC',
    'Persistence': 'PERSIST', 'Discovery': 'DISCOVER',
    'Defense Evasion': 'EVASION', 'Impact': 'IMPACT',
  })[t] || t;
}
function sevColor(s) {
  if (s === 'critical') return 'var(--hot)';
  if (s === 'high')     return 'var(--warm)';
  if (s === 'medium')   return 'var(--cool)';
  return 'var(--ink-3)';
}
function riskColor(r) {
  if (r === 'high')   return 'var(--hot)';
  if (r === 'medium') return 'var(--warm)';
  return 'var(--ink-3)';
}

/* ===========================================================
   PLAN VIEW (kept from v1 - clean approval / preview)
   =========================================================== */
function PlanView({ onRun }) {
  const tactics = useMemo(() => {
    const tally = {};
    RUN.chain.forEach(s => tally[s.tactic] = (tally[s.tactic]||0)+1);
    return tally;
  }, []);
  const byCategory = useMemo(() => {
    const g = {};
    RUN.infra.resources.forEach(r => {
      (g[r.category] = g[r.category] || []).push(r);
    });
    return g;
  }, []);

  return (
    <div style={{ maxWidth: 1320, margin: '0 auto', padding: '40px 28px 80px' }}>
      <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr', gap: 36, alignItems: 'flex-start', marginBottom: 36 }}>
        <div>
          <div className="eyebrow">Threat actor · adversary emulation</div>
          <h1 className="h-1" style={{ marginTop: 12, lineHeight: 1.25, marginBottom: 24, paddingBottom: 8 }}>
            <span style={{ fontFamily: 'var(--mono)', fontSize: '0.32em', letterSpacing: '0.16em', color: 'var(--ink-3)', display: 'block', marginBottom: 14, fontWeight: 500, lineHeight: 1 }}>RUN · {RUN.run_id}</span>
            AMBERSQUID <span className="em">cryptomining</span>
          </h1>
          <p className="lede" style={{ marginTop: 0, maxWidth: 620 }}>
            Burst-provisioning miner infrastructure across Amplify, ECS Fargate, SageMaker,
            CodeBuild, and Auto Scaling - then disabling CloudTrail and deleting the trail
            of evidence. {RUN.chain.length} kill-chain steps, {RUN.credentials.length} credential pivots.
          </p>
          <div style={{ display: 'flex', gap: 18, marginTop: 24, flexWrap: 'wrap', fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--ink-3)', textTransform: 'uppercase', letterSpacing: '0.14em' }}>
            <span><b style={{ color: 'var(--ink)' }}>ATTRIB</b> {RUN.attribution}</span>
            <span><b style={{ color: 'var(--ink)' }}>MOTIVATION</b> {RUN.motivation}</span>
            <span><b style={{ color: 'var(--ink)' }}>PLATFORM</b> {RUN.platform.toUpperCase()}</span>
            <span><b style={{ color: 'var(--ink)' }}>REGION</b> {RUN.region}</span>
          </div>
          <div style={{ marginTop: 12, fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--ink-3)', textTransform: 'uppercase', letterSpacing: '0.14em' }}>
            SOURCE · <a href={RUN.source} style={{ color: 'var(--cool)', textDecoration: 'none' }}>{RUN.source.replace(/https?:\/\//, '')}</a>
          </div>
        </div>

        <div style={{ border: '1px solid var(--rule-2)', background: 'var(--bg-1)', padding: '20px 22px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
            <span style={{ fontFamily: 'var(--mono)', fontSize: 10.5, textTransform: 'uppercase', letterSpacing: '0.16em', color: 'var(--ok)', display: 'inline-flex', alignItems: 'center', gap: 6 }}>
              <span style={{ width: 7, height: 7, background: 'var(--ok)', borderRadius: '50%', boxShadow: '0 0 8px var(--ok)' }} />
              READY TO RUN
            </span>
            <span style={{ fontFamily: 'var(--mono)', fontSize: 10, color: 'var(--ink-3)', textTransform: 'uppercase', letterSpacing: '0.14em' }}>
              FIDELITY {(RUN.fidelity_score * 100).toFixed(0)}%
            </span>
          </div>

          <table style={{ width: '100%', fontFamily: 'var(--mono)', fontSize: 11.5, color: 'var(--ink-2)', borderCollapse: 'collapse' }}>
            <tbody>
              <tr><td style={{ padding: '6px 0', color: 'var(--ink-3)', textTransform: 'uppercase', letterSpacing: '0.12em', fontSize: 10 }}>STEPS</td><td style={{ textAlign: 'right', color: 'var(--ink)' }}>{RUN.chain.length}</td></tr>
              <tr><td style={{ padding: '6px 0', color: 'var(--ink-3)', textTransform: 'uppercase', letterSpacing: '0.12em', fontSize: 10 }}>TECHNIQUES</td><td style={{ textAlign: 'right', color: 'var(--ink)' }}>{RUN.chain.length}</td></tr>
              <tr><td style={{ padding: '6px 0', color: 'var(--ink-3)', textTransform: 'uppercase', letterSpacing: '0.12em', fontSize: 10 }}>RESOURCES</td><td style={{ textAlign: 'right', color: 'var(--ink)' }}>{RUN.infra.resources.length} · {RUN.infra.vpc_cidr}</td></tr>
              <tr><td style={{ padding: '6px 0', color: 'var(--ink-3)', textTransform: 'uppercase', letterSpacing: '0.12em', fontSize: 10 }}>STANDING</td><td style={{ textAlign: 'right', color: 'var(--ink)' }}>{fmtMoney(RUN.infra.hourly_cost_usd)}/hr · {fmtMoney(RUN.infra.monthly_cost_usd)}/mo</td></tr>
              <tr><td style={{ padding: '6px 0', color: 'var(--ink-3)', textTransform: 'uppercase', letterSpacing: '0.12em', fontSize: 10 }}>PER RUN</td><td style={{ textAlign: 'right', color: 'var(--ink)' }}>{fmtMoney(RUN.infra.per_run_cost_usd)}</td></tr>
              <tr><td style={{ padding: '6px 0', color: 'var(--ink-3)', textTransform: 'uppercase', letterSpacing: '0.12em', fontSize: 10 }}>EST. RUNTIME</td><td style={{ textAlign: 'right', color: 'var(--ink)' }}>~{RUN.duration_real_min} min</td></tr>
            </tbody>
          </table>

          <button onClick={onRun} className="btn" style={{ width: '100%', justifyContent: 'center', marginTop: 18, padding: '12px 16px', fontSize: 13.5 }}>
            ▶ &nbsp;Run emulation &nbsp;<span style={{ fontFamily: 'var(--mono)', fontSize: 10.5, opacity: 0.7, letterSpacing: '0.14em' }}>(playback)</span>
          </button>
          <div style={{ marginTop: 10, fontFamily: 'var(--mono)', fontSize: 9.5, color: 'var(--ink-4)', textTransform: 'uppercase', letterSpacing: '0.14em', textAlign: 'center' }}>
            no AWS calls · animated from approved plan
          </div>
        </div>
      </div>

      {/* TACTICS STRIP */}
      <div style={{ display: 'flex', gap: 0, border: '1px solid var(--rule)', marginBottom: 28 }}>
        {Object.entries(tactics).map(([t, n], i) => (
          <div key={t} style={{ flex: 1, padding: '14px 18px', borderRight: i < Object.keys(tactics).length - 1 ? '1px solid var(--rule)' : 'none', background: 'var(--bg-1)' }}>
            <div style={{ fontFamily: 'var(--mono)', fontSize: 10, color: 'var(--ink-3)', textTransform: 'uppercase', letterSpacing: '0.16em' }}>{shortTactic(t)}</div>
            <div style={{ fontFamily: 'var(--sans)', fontSize: 22, fontWeight: 600, color: 'var(--ink)', letterSpacing: '-0.02em', marginTop: 4 }}>{n} <span style={{ fontSize: 12, fontWeight: 400, color: 'var(--ink-3)', fontFamily: 'var(--mono)' }}>step{n>1?'s':''}</span></div>
          </div>
        ))}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr 1fr', gap: 16 }}>
        <div style={{ border: '1px solid var(--rule)', background: 'var(--bg-1)' }}>
          <div className="block-head">KILL CHAIN · {RUN.chain.length} STEPS</div>
          <div style={{ padding: '8px 0' }}>
            {RUN.chain.map((s) => (
              <div key={s.step} style={{
                display: 'grid', gridTemplateColumns: '40px 1fr auto',
                padding: '10px 18px',
                borderBottom: s.step < RUN.chain.length ? '1px dashed var(--rule)' : 'none',
                gap: 12, alignItems: 'baseline',
              }}>
                <span style={{ fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--ink-4)' }}>0{s.step > 9 ? '' : '0'}{s.step}</span>
                <div>
                  <div style={{ fontFamily: 'var(--sans)', fontSize: 13.5, color: 'var(--ink)', fontWeight: 500, letterSpacing: '-0.005em' }}>{s.name}</div>
                  <div style={{ fontFamily: 'var(--mono)', fontSize: 10, color: 'var(--ink-3)', textTransform: 'uppercase', letterSpacing: '0.14em', marginTop: 2 }}>
                    <span style={{ color: 'var(--cool)' }}>{s.technique}</span> · {shortTactic(s.tactic)} {s.simulated ? '· SIM' : ''}
                  </div>
                </div>
                <span style={{
                  fontFamily: 'var(--mono)', fontSize: 9.5, padding: '2px 6px',
                  border: `1px solid ${riskColor(s.risk)}`, color: riskColor(s.risk),
                  textTransform: 'uppercase', letterSpacing: '0.14em',
                }}>{s.risk}</span>
              </div>
            ))}
          </div>
        </div>

        <div style={{ border: '1px solid var(--rule)', background: 'var(--bg-1)' }}>
          <div className="block-head">CREDENTIAL CHAIN · {RUN.credentials.length} SESSIONS</div>
          <div style={{ padding: '6px 0' }}>
            {RUN.credentials.map((c, i) => (
              <div key={c.id} style={{
                padding: '14px 18px',
                borderBottom: i < RUN.credentials.length - 1 ? '1px dashed var(--rule)' : 'none',
              }}>
                <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between', gap: 8, marginBottom: 6 }}>
                  <span style={{ fontFamily: 'var(--mono)', fontSize: 12, color: c.type === 'static_key' ? 'var(--hot)' : 'var(--cool)', fontWeight: 600 }}>{c.id}</span>
                  <span style={{ fontFamily: 'var(--mono)', fontSize: 9.5, color: 'var(--ink-3)', textTransform: 'uppercase', letterSpacing: '0.14em' }}>{c.type === 'static_key' ? 'STATIC KEY' : 'STS'}</span>
                </div>
                <div style={{ fontFamily: 'var(--sans)', fontSize: 12.5, color: 'var(--ink-2)', lineHeight: 1.5 }}>{c.short}</div>
                <div style={{ fontFamily: 'var(--mono)', fontSize: 9.5, color: 'var(--ink-3)', textTransform: 'uppercase', letterSpacing: '0.14em', marginTop: 6 }}>
                  via <span style={{ color: 'var(--cool)' }}>{c.source_technique}</span> · used in {c.used_in_phases.length} phases
                </div>
              </div>
            ))}
          </div>
        </div>

        <div style={{ border: '1px solid var(--rule)', background: 'var(--bg-1)' }}>
          <div className="block-head">INFRA · {RUN.infra.resources.length} RESOURCES</div>
          {Object.entries(byCategory).map(([cat, items]) => (
            <div key={cat} style={{ padding: '12px 18px', borderBottom: '1px dashed var(--rule)' }}>
              <div style={{ fontFamily: 'var(--mono)', fontSize: 9.5, color: 'var(--ink-3)', textTransform: 'uppercase', letterSpacing: '0.18em', marginBottom: 8 }}>
                {cat.replace('_', ' ')} · {items.length}
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                {items.map(r => (
                  <span key={r.name} title={r.type} style={{
                    fontFamily: 'var(--mono)', fontSize: 9.5,
                    padding: '2px 6px', border: '1px solid var(--rule-2)',
                    color: 'var(--ink-2)', letterSpacing: '0.04em',
                  }}>{r.name.replace('ambersquid-', '')}</span>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

/* ===========================================================
   RUNNING VIEW - calm chain + click-to-inspect
   =========================================================== */
function RunningView({ onComplete, onAbort }) {
  const [tickMs, setTickMs] = useState(0);
  const [speed, setSpeed] = useState(1);
  const [paused, setPaused] = useState(false);
  const [openStep, setOpenStep] = useState(null); // step number user explicitly opened (or null for "follow current")
  const [followCurrent, setFollowCurrent] = useState(true);
  const lastTickRef = useRef(performance.now());
  const completedRef = useRef(false);

  // virtual time advance - cap at totalMs so the display doesn't run away
  useEffect(() => {
    let raf;
    function step(now) {
      const dt = now - lastTickRef.current;
      lastTickRef.current = now;
      if (!paused) setTickMs(t => Math.min(t + dt * speed, schedule[schedule.length - 1].end_ms));
      raf = requestAnimationFrame(step);
    }
    raf = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf);
  }, [paused, speed]);

  // schedule
  const schedule = useMemo(() => {
    let t = 0;
    return RUN.chain.map(s => {
      const start = t;
      const dur = s.duration_s * 1000;
      t += dur;
      return { ...s, start_ms: start, end_ms: start + dur };
    });
  }, []);
  const totalMs = schedule[schedule.length - 1].end_ms;

  // current step number (1-indexed)
  const currentStep = useMemo(() => {
    let cur = schedule[0];
    for (const s of schedule) if (tickMs >= s.start_ms) cur = s;
    return cur;
  }, [tickMs, schedule]);

  // step to display in the focal area
  const focusedStep = useMemo(() => {
    if (openStep != null) return schedule.find(s => s.step === openStep) || currentStep;
    return currentStep;
  }, [openStep, currentStep, schedule]);

  // detections fired (for chain-rail status only - no panel)
  const firedDetections = useMemo(() => {
    const fired = {};
    for (const s of schedule) {
      if (!s.detection) continue;
      if (tickMs < s.start_ms) continue;
      const fireT = s.start_ms + (s.detection.latency_s || 0) * 1000;
      if (tickMs >= fireT) fired[s.detection.rule] = { ...s.detection, fired_at: fireT, step: s.step };
    }
    return fired;
  }, [tickMs, schedule]);

  const activeCred = useMemo(() => {
    let cred = 'victim_creds';
    for (const s of schedule) if (tickMs >= s.start_ms && s.credential) cred = s.credential;
    return cred;
  }, [tickMs, schedule]);

  const visibleEvents = useMemo(() => {
    const out = [];
    for (const s of schedule) {
      if (tickMs < s.start_ms) break;
      s.events.forEach(e => {
        const t = s.start_ms + e.t_offset_s * 1000;
        if (tickMs >= t) out.push({ ...e, _t: t, _step: s });
      });
    }
    return out.slice(-30);
  }, [tickMs, schedule]);

  // run completion - fires exactly once when tickMs first reaches totalMs
  useEffect(() => {
    if (tickMs >= totalMs && !paused && !completedRef.current) {
      completedRef.current = true;
      const t = setTimeout(() => {
        // snapshot firedDetections at completion time
        const finalFired = {};
        for (const s of schedule) {
          if (!s.detection) continue;
          const fireT = s.start_ms + (s.detection.latency_s || 0) * 1000;
          if (totalMs >= fireT) finalFired[s.detection.rule] = { ...s.detection, fired_at: fireT, step: s.step };
        }
        onComplete({ tickMs: totalMs, firedDetections: finalFired, totalMs });
      }, 1200);
      return () => clearTimeout(t);
    }
  }, [tickMs, totalMs, paused, onComplete, schedule]);

  const firedCount = Object.keys(firedDetections).length;
  const armedTotal = RUN.detection_registry.length;

  // chain rail click handler
  function handleStepClick(stepNum) {
    setOpenStep(stepNum);
    setFollowCurrent(false);
  }
  function resumeFollow() {
    setOpenStep(null);
    setFollowCurrent(true);
  }

  return (
    <div style={{ maxWidth: 1320, margin: '0 auto', padding: '20px 28px 80px' }}>
      {/* HEADER */}
      <div style={{ display: 'flex', gap: 18, alignItems: 'center', marginBottom: 16 }}>
        <div>
          <div className="eyebrow" style={{ marginBottom: 6 }}>LIVE RUN · IN PROGRESS</div>
          <h1 style={{ fontFamily: 'var(--sans)', fontSize: 24, fontWeight: 600, margin: 0, letterSpacing: '-0.02em' }}>
            AMBERSQUID · <span style={{ color: 'var(--cool)' }}>{RUN.run_id}</span>
          </h1>
        </div>
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 10, alignItems: 'center' }}>
          <div style={{ display: 'inline-flex', border: '1px solid var(--rule-2)' }}>
            {[1, 2, 5].map(x => (
              <button key={x} onClick={() => setSpeed(x)} style={{
                fontFamily: 'var(--mono)', fontSize: 10.5, fontWeight: 500,
                padding: '6px 12px',
                background: speed === x ? 'var(--ink)' : 'transparent',
                color: speed === x ? 'var(--bg)' : 'var(--ink-2)',
                border: 0, cursor: 'pointer', letterSpacing: '0.14em',
              }}>{x}×</button>
            ))}
          </div>
          <button onClick={() => setPaused(p => !p)} className="btn outline" style={{ padding: '7px 12px', fontSize: 11.5 }}>
            {paused ? '▶ Resume' : '⏸ Pause'}
          </button>
          <button onClick={onAbort} style={{
            fontFamily: 'var(--mono)', fontSize: 10.5, background: 'transparent', color: 'var(--ink-3)',
            border: '1px solid var(--rule-2)', padding: '8px 12px', cursor: 'pointer',
            textTransform: 'uppercase', letterSpacing: '0.14em',
          }}>Abort</button>
        </div>
      </div>

      {/* SCOREBOARD STRIP - quiet, no detection firing telemetry (we don't have it) */}
      <div style={{
        display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 0,
        border: '1px solid var(--rule)', background: 'var(--bg-1)',
        marginBottom: 14,
      }}>
        <KPI label="ELAPSED"    value={fmtTime(tickMs)} sub={`/ ${fmtTime(totalMs)}`} />
        <KPI label="CURRENT"    value={`${currentStep.step}/${schedule.length}`} sub={currentStep.technique} subColor="var(--cool)" />
        <KPI label="ACTIVE CRED" value={activeCred} valueColor={activeCred === 'victim_creds' ? 'var(--hot)' : 'var(--cool)'} sub={activeCred === 'victim_creds' ? 'static · long-lived' : 'sts · 3600s'} />
      </div>

      {/* MAIN: chain rail (clickable accordion) | focal story */}
      <div style={{ display: 'grid', gridTemplateColumns: '260px 1fr', gap: 14 }}>

        {/* CHAIN RAIL - click any step to inspect */}
        <div style={{ border: '1px solid var(--rule)', background: 'var(--bg-1)', position: 'sticky', top: 130, alignSelf: 'start', overflow: 'hidden' }}>
          <div style={{ padding: '10px 14px', borderBottom: '1px solid var(--rule)', background: 'var(--bg-2)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontFamily: 'var(--mono)', fontSize: 10.5, color: 'var(--ink-2)', textTransform: 'uppercase', letterSpacing: '0.16em', fontWeight: 500 }}>
              CHAIN · {schedule.length} STEPS
            </span>
            {!followCurrent && (
              <button onClick={resumeFollow} style={{
                fontFamily: 'var(--mono)', fontSize: 9.5, background: 'transparent', color: 'var(--cool)',
                border: '1px solid var(--cool)', padding: '2px 7px', cursor: 'pointer',
                textTransform: 'uppercase', letterSpacing: '0.14em',
              }}>FOLLOW LIVE</button>
            )}
          </div>
          <div style={{ position: 'relative', padding: '10px 0' }}>
            <div style={{ position: 'absolute', left: 30, top: 10, bottom: 10, width: 1, background: 'var(--rule-2)' }} />
            {schedule.map(s => {
              const done = tickMs >= s.end_ms;
              const cur  = tickMs >= s.start_ms && tickMs < s.end_ms;
              const isOpen = focusedStep.step === s.step;
              const dotColor = done ? 'var(--ok)' : cur ? 'var(--hot)' : 'var(--ink-4)';
              return (
                <button key={s.step} onClick={() => handleStepClick(s.step)} style={{
                  all: 'unset', cursor: 'pointer', boxSizing: 'border-box',
                  display: 'grid', gridTemplateColumns: '60px 1fr',
                  alignItems: 'center', width: '100%',
                  padding: '8px 12px',
                  background: isOpen ? 'rgba(106,168,255,0.06)' : 'transparent',
                  borderLeft: isOpen ? '2px solid var(--cool)' : '2px solid transparent',
                  opacity: done || cur ? 1 : 0.6,
                  transition: 'background 0.15s, opacity 0.3s',
                }}>
                  <div style={{ position: 'relative', display: 'flex', justifyContent: 'center' }}>
                    <span style={{
                      width: cur ? 14 : 9, height: cur ? 14 : 9, borderRadius: '50%',
                      background: dotColor,
                      boxShadow: cur ? `0 0 12px ${dotColor}` : 'none',
                      border: cur ? '2px solid var(--bg-1)' : 'none',
                      transition: 'all 0.3s',
                    }} />
                  </div>
                  <div style={{ minWidth: 0 }}>
                    <div style={{
                      fontFamily: 'var(--sans)', fontSize: 12.5,
                      color: isOpen ? 'var(--cool)' : cur ? 'var(--ink)' : done ? 'var(--ink-2)' : 'var(--ink-3)',
                      fontWeight: isOpen || cur ? 600 : 500,
                      letterSpacing: '-0.005em', lineHeight: 1.3,
                      wordBreak: 'break-word', overflowWrap: 'break-word',
                    }}>{NARRATIVES[s.technique]?.headline || s.name}</div>
                    <div style={{ fontFamily: 'var(--mono)', fontSize: 9.5, color: 'var(--ink-3)', textTransform: 'uppercase', letterSpacing: '0.14em', marginTop: 3 }}>
                      <span style={{ color: cur ? 'var(--cool)' : 'var(--ink-3)' }}>{s.technique}</span>
                      {s.simulated && <span style={{ color: 'var(--ink-4)', marginLeft: 6 }}>· SIM</span>}
                    </div>
                  </div>
                </button>
              );
            })}
          </div>
          <div style={{
            padding: '8px 14px', borderTop: '1px solid var(--rule)', background: 'var(--bg-2)',
            fontFamily: 'var(--mono)', fontSize: 9.5, color: 'var(--ink-4)',
            textTransform: 'uppercase', letterSpacing: '0.14em', textAlign: 'center',
          }}>
            CLICK ANY STEP TO INSPECT
          </div>
        </div>

        {/* FOCAL - story card for the focused step + collapsible cloudtrail */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          <StoryCard step={focusedStep} tickMs={tickMs} fired={firedDetections} isCurrent={focusedStep.step === currentStep.step} />
          <CloudTrailTail events={visibleEvents} focusedStep={focusedStep} />
        </div>
      </div>
    </div>
  );
}

function KPI({ label, value, valueColor, sub, subColor }) {
  return (
    <div style={{ padding: '12px 16px', borderRight: '1px solid var(--rule)' }}>
      <div style={{ fontFamily: 'var(--mono)', fontSize: 9.5, color: 'var(--ink-3)', textTransform: 'uppercase', letterSpacing: '0.16em' }}>{label}</div>
      <div style={{ fontFamily: 'var(--sans)', fontSize: 20, fontWeight: 600, color: valueColor || 'var(--ink)', letterSpacing: '-0.02em', marginTop: 4 }}>{value}</div>
      <div style={{ fontFamily: 'var(--mono)', fontSize: 9.5, color: subColor || 'var(--ink-4)', textTransform: 'uppercase', letterSpacing: '0.14em', marginTop: 2 }}>{sub}</div>
    </div>
  );
}

/* STORY CARD - narrates the focused step */
function StoryCard({ step, tickMs, fired, isCurrent }) {
  const narrative = NARRATIVES[step.technique] || { headline: step.name, body: '', watch_for: '', consequence: '' };
  const stepStart = step.start_ms || 0;

  const eventStatus = (e) => {
    const t = stepStart + e.t_offset_s * 1000;
    if (tickMs >= t + 300) return 'done';
    if (tickMs >= t)       return 'current';
    return 'pending';
  };

  const det = step.detection;
  const detRule = det?.rule;
  const fireT = det ? stepStart + det.latency_s * 1000 : null;
  const detFired = detRule && fired[detRule];
  const detPending = detRule && !detFired && tickMs < fireT && isCurrent;
  const detMissed = detRule && !detFired && tickMs >= fireT;
  const beforeStep = tickMs < stepStart;

  const visibility =
    step.simulated ? 'SIMULATED · no API calls' :
    step.documented ? 'DOCUMENTED · no API calls' :
    (step.events && step.events.length === 0) ? 'DATA PLANE · no CloudTrail' :
    'CONTROL PLANE · CloudTrail';

  const visColor = step.simulated || step.documented || (step.events||[]).length === 0 ? 'var(--ink-3)' : 'var(--cool)';

  return (
    <div style={{ border: '1px solid var(--rule-2)', background: 'var(--bg-1)', overflow: 'hidden' }}>
      <div style={{
        display: 'flex', alignItems: 'center', gap: 12,
        padding: '12px 18px', borderBottom: '1px solid var(--rule)', background: 'var(--bg-2)',
        fontFamily: 'var(--mono)', fontSize: 10.5, textTransform: 'uppercase', letterSpacing: '0.16em',
        color: 'var(--ink-3)', flexWrap: 'wrap',
      }}>
        <span><b style={{ color: 'var(--ink)' }}>STEP {step.step}/{RUN.chain.length}</b></span>
        <span style={{ color: 'var(--cool)' }}>{step.technique}</span>
        <span>{shortTactic(step.tactic)}</span>
        {!isCurrent && (
          <span style={{ color: 'var(--warm)', display: 'inline-flex', alignItems: 'center', gap: 4 }}>
            <span style={{ width: 6, height: 6, background: 'var(--warm)', borderRadius: '50%' }} />
            INSPECTING
          </span>
        )}
        <span style={{ marginLeft: 'auto', color: visColor }}>{visibility}</span>
      </div>

      <div style={{ padding: '22px 24px 18px' }}>
        <div style={{ fontFamily: 'var(--sans)', fontSize: 22, fontWeight: 600, color: 'var(--ink)', letterSpacing: '-0.018em', lineHeight: 1.2 }}>
          {narrative.headline}
        </div>
        <p style={{ fontFamily: 'var(--sans)', fontSize: 14.5, color: 'var(--ink-2)', lineHeight: 1.55, margin: '10px 0 0' }}>
          {narrative.body}
        </p>
      </div>

      <div style={{ padding: '12px 24px', borderTop: '1px dashed var(--rule)', display: 'flex', alignItems: 'center', gap: 18, flexWrap: 'wrap' }}>
        <span style={{ fontFamily: 'var(--mono)', fontSize: 9.5, color: 'var(--ink-3)', textTransform: 'uppercase', letterSpacing: '0.16em' }}>USING</span>
        {step.credential ? (
          <span style={{
            fontFamily: 'var(--mono)', fontSize: 11, fontWeight: 600,
            color: step.credential === 'victim_creds' ? 'var(--hot)' : 'var(--cool)',
            padding: '3px 8px', border: `1px solid ${step.credential === 'victim_creds' ? 'var(--hot)' : 'var(--cool)'}`,
            background: step.credential === 'victim_creds' ? 'rgba(255,75,110,0.06)' : 'rgba(106,168,255,0.06)',
          }}>{step.credential}</span>
        ) : (
          <span style={{ fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--ink-3)' }}>- no credential yet</span>
        )}
        {step.services && step.services.length > 0 && (
          <>
            <span style={{ fontFamily: 'var(--mono)', fontSize: 9.5, color: 'var(--ink-3)', textTransform: 'uppercase', letterSpacing: '0.16em', marginLeft: 'auto' }}>SERVICES</span>
            <span style={{ fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--ink-2)' }}>
              {step.services.join(' · ')}
            </span>
          </>
        )}
      </div>

      {step.events && step.events.length > 0 && (
        <div style={{ borderTop: '1px dashed var(--rule)' }}>
          <div style={{ padding: '12px 24px 6px', display: 'flex', justifyContent: 'space-between', alignItems: 'baseline' }}>
            <span style={{ fontFamily: 'var(--mono)', fontSize: 9.5, color: 'var(--ink-3)', textTransform: 'uppercase', letterSpacing: '0.16em' }}>API SEQUENCE</span>
            <span style={{ fontFamily: 'var(--mono)', fontSize: 9.5, color: 'var(--ink-4)', textTransform: 'uppercase', letterSpacing: '0.14em' }}>
              {beforeStep ? 'pending' : step.events.filter(e => eventStatus(e) !== 'pending').length + '/' + step.events.length}
            </span>
          </div>
          <div style={{ padding: '0 24px 14px' }}>
            {step.events.map((e, i) => {
              const status = beforeStep ? 'pending' : eventStatus(e);
              const icon = status === 'done' ? '✓' : status === 'current' ? '►' : '○';
              const iconColor = status === 'done' ? 'var(--ok)' : status === 'current' ? 'var(--cool)' : 'var(--ink-4)';
              return (
                <div key={i} style={{
                  display: 'grid', gridTemplateColumns: '20px 130px 1fr auto', gap: 10,
                  padding: '5px 0',
                  fontFamily: 'var(--mono)', fontSize: 11.5,
                  color: status === 'pending' ? 'var(--ink-4)' : 'var(--ink-2)',
                  alignItems: 'baseline',
                }}>
                  <span style={{ color: iconColor, fontWeight: 600 }}>{icon}</span>
                  <span style={{ color: status === 'pending' ? 'var(--ink-4)' : 'var(--cool)' }}>{e.eventSource.replace('.amazonaws.com', '')}</span>
                  <span style={{ color: status === 'pending' ? 'var(--ink-4)' : 'var(--ink)' }}>{e.eventName}</span>
                  <span style={{ color: e.note?.includes('⚠') || e.note?.includes('CRITICAL') || e.note?.includes('CANARY') ? 'var(--hot)' : 'var(--ink-3)', fontSize: 10.5 }}>
                    {e.note || (e.simulated ? '(simulated)' : '')}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* DETECTION RULE SHIPPED + WATCH FOR + CONSEQUENCE */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', borderTop: '1px solid var(--rule)' }}>
        <div style={{ padding: '14px 24px', borderRight: '1px solid var(--rule)' }}>
          <div style={{ fontFamily: 'var(--mono)', fontSize: 9.5, color: 'var(--ink-3)', textTransform: 'uppercase', letterSpacing: '0.16em', marginBottom: 8 }}>
            DETECTION RULE SHIPPED
          </div>
          {!det ? (
            <div style={{ fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--ink-4)' }}>- no Sigma rule for this technique</div>
          ) : (
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{ width: 8, height: 8, background: 'var(--cool)', borderRadius: '50%', boxShadow: '0 0 6px var(--cool)' }} />
                <span style={{ fontFamily: 'var(--mono)', fontSize: 11.5, color: 'var(--cool)', fontWeight: 600, letterSpacing: '0.06em' }}>
                  {detRule}
                </span>
                {RUN.detection_registry.find(d => d.rule === detRule) && (
                  <span style={{
                    fontFamily: 'var(--mono)', fontSize: 9.5,
                    color: sevColor(RUN.detection_registry.find(d => d.rule === detRule).severity),
                    textTransform: 'uppercase', letterSpacing: '0.14em',
                    border: `1px solid ${sevColor(RUN.detection_registry.find(d => d.rule === detRule).severity)}`,
                    padding: '1px 6px',
                  }}>
                    {RUN.detection_registry.find(d => d.rule === detRule).severity}
                  </span>
                )}
              </div>
              <div style={{ fontFamily: 'var(--mono)', fontSize: 10, color: 'var(--ink-3)', textTransform: 'uppercase', letterSpacing: '0.14em', marginTop: 6 }}>
                source: {RUN.detection_registry.find(d => d.rule === detRule)?.source || 'AWS CloudTrail'}
              </div>
            </div>
          )}
          {narrative.watch_for && (
            <p style={{ fontFamily: 'var(--sans)', fontSize: 12.5, color: 'var(--ink-3)', lineHeight: 1.55, margin: '10px 0 0' }}>
              <span style={{ color: 'var(--ink-2)' }}>Watch for: </span>{narrative.watch_for}
            </p>
          )}
        </div>
        <div style={{ padding: '14px 24px' }}>
          <div style={{ fontFamily: 'var(--mono)', fontSize: 9.5, color: 'var(--ink-3)', textTransform: 'uppercase', letterSpacing: '0.16em', marginBottom: 8 }}>
            CONSEQUENCE
          </div>
          <p style={{ fontFamily: 'var(--sans)', fontSize: 13.5, color: 'var(--ink-2)', lineHeight: 1.55, margin: 0 }}>
            {narrative.consequence}
          </p>
        </div>
      </div>
    </div>
  );
}

/* CloudTrail tail - collapsible */
function CloudTrailTail({ events, focusedStep }) {
  const [open, setOpen] = useState(false);
  const scrollRef = useRef(null);
  useEffect(() => {
    if (open && scrollRef.current) scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
  }, [events, open]);

  // recent count badge
  const recent = events.length;

  return (
    <div style={{ border: '1px solid var(--rule)', background: 'var(--bg-1)' }}>
      <button onClick={() => setOpen(o => !o)} style={{
        all: 'unset', cursor: 'pointer', width: '100%',
        display: 'flex', alignItems: 'center', gap: 12,
        padding: '10px 14px', background: 'var(--bg-2)',
        borderBottom: open ? '1px solid var(--rule)' : 'none',
        fontFamily: 'var(--mono)', fontSize: 10.5, textTransform: 'uppercase', letterSpacing: '0.16em',
        color: 'var(--ink-2)', fontWeight: 500,
      }}>
        <span>{open ? '▼' : '▶'}</span>
        <span>CLOUDTRAIL · RAW EVENTS</span>
        <span style={{ marginLeft: 'auto', color: 'var(--ink-3)' }}>{recent} recent</span>
      </button>
      {open && (
        <div ref={scrollRef} style={{
          height: 240, overflow: 'auto',
          padding: '10px 14px',
          fontFamily: 'var(--mono)', fontSize: 11, lineHeight: 1.6,
          color: 'var(--ink-2)',
        }}>
          {events.length === 0 ? (
            <div style={{ color: 'var(--ink-4)', fontStyle: 'italic' }}>waiting for events…</div>
          ) : events.map((e, i) => (
            <div key={i} style={{ display: 'flex', gap: 10, marginBottom: 2 }}>
              <span style={{ color: 'var(--ink-4)', width: 48, flexShrink: 0 }}>+{(e._t / 1000).toFixed(1)}s</span>
              <span style={{ color: 'var(--cool)', width: 110, flexShrink: 0 }}>{e.eventSource.replace('.amazonaws.com', '')}</span>
              <span style={{ color: e.simulated ? 'var(--ink-3)' : 'var(--ink)' }}>{e.eventName}</span>
              {e.note && <span style={{ color: 'var(--warm)', marginLeft: 8 }}>⚠ {e.note}</span>}
              {e.simulated && <span style={{ color: 'var(--ink-4)', marginLeft: 8 }}>(sim)</span>}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

/* ===========================================================
   COMPLETE VIEW
   =========================================================== */
function CompleteView({ result, onReset }) {
  const shipped = RUN.detection_registry.length;

  return (
    <div style={{ maxWidth: 1320, margin: '0 auto', padding: '40px 28px 80px' }}>
      <div style={{ display: 'flex', alignItems: 'flex-end', gap: 18, marginBottom: 28 }}>
        <div>
          <div className="eyebrow">RUN COMPLETE · EVIDENCE SEALED</div>
          <h1 className="h-1" style={{ marginTop: 12, lineHeight: 1.25, marginBottom: 14, paddingBottom: 6 }}>
            AMBERSQUID chain <span className="em">landed</span>.
          </h1>
          <p className="lede" style={{ marginTop: 0, maxWidth: 600 }}>
            All {RUN.chain.length} steps executed across {RUN.credentials.length} credential pivots in {fmtTime(result.totalMs)} of virtual time.
            <b style={{ color: 'var(--ink)' }}> {shipped} Sigma rules</b> shipped as part of the evidence package - take them to your SIEM and replay this run against them offline.
          </p>
        </div>
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 10 }}>
          <button className="btn outline" onClick={onReset}>Replay run</button>
          <a className="btn" href="MayaTrail Landing.html">Back to product →</a>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 0, border: '1px solid var(--rule)', marginBottom: 28 }}>
        <KPI label="TECHNIQUES RUN"      value={`${RUN.chain.length}`} sub={`${RUN.chain.filter(s=>!s.simulated).length} executed · ${RUN.chain.filter(s=>s.simulated).length} simulated`} />
        <KPI label="RULES SHIPPED"       value={`${shipped}`} sub="sigma · mitre-aligned" subColor="var(--cool)" />
        <KPI label="IR PLAYBOOK"         value="739 lines" sub="prep · ident · contain · recover" subColor="var(--cool)" />
        <KPI label="EVIDENCE BUNDLE"     value="4 files" sub="signed · hash-chained" subColor="var(--cool)" />
      </div>

      {/* THREE PILLARS OF OUTPUT */}
      <div style={{ marginBottom: 28, padding: '20px 24px', border: '1px solid var(--rule-2)', background: 'linear-gradient(135deg, rgba(106,168,255,0.04), transparent 60%)' }}>
        <div style={{ fontFamily: 'var(--mono)', fontSize: 10.5, color: 'var(--cool)', textTransform: 'uppercase', letterSpacing: '0.18em', marginBottom: 14 }}>WHAT YOU TAKE HOME · THREE DELIVERABLES</div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 20 }}>
          <div>
            <div style={{ fontFamily: 'var(--sans)', fontSize: 18, fontWeight: 600, color: 'var(--ink)', letterSpacing: '-0.015em', marginBottom: 6 }}>Detection content</div>
            <div style={{ fontFamily: 'var(--sans)', fontSize: 13.5, color: 'var(--ink-2)', lineHeight: 1.5 }}>{shipped} Sigma rules, MITRE-aligned. Drop into your repo, fires next time AMBERSQUID lands.</div>
          </div>
          <div>
            <div style={{ fontFamily: 'var(--sans)', fontSize: 18, fontWeight: 600, color: 'var(--ink)', letterSpacing: '-0.015em', marginBottom: 6 }}>IR playbook</div>
            <div style={{ fontFamily: 'var(--sans)', fontSize: 13.5, color: 'var(--ink-2)', lineHeight: 1.5 }}>Full incident-response runbook. Prep / identify / contain / eradicate / recover - with real bash + AWS CLI queries.</div>
          </div>
          <div>
            <div style={{ fontFamily: 'var(--sans)', fontSize: 18, fontWeight: 600, color: 'var(--ink)', letterSpacing: '-0.015em', marginBottom: 6 }}>Forensic evidence</div>
            <div style={{ fontFamily: 'var(--sans)', fontSize: 13.5, color: 'var(--ink-2)', lineHeight: 1.5 }}>Signed CloudTrail dump + MITRE map. Hash-chained, replayable offline, audit-ready.</div>
          </div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr', gap: 16 }}>
        <div style={{ border: '1px solid var(--rule)', background: 'var(--bg-1)' }}>
          <div className="block-head">DETECTION CONTENT SHIPPED · {shipped} RULES</div>
          {RUN.detection_registry.map(d => (
            <div key={d.rule} style={{ padding: '14px 18px', borderBottom: '1px dashed var(--rule)', display: 'grid', gridTemplateColumns: '1fr auto', gap: 16, alignItems: 'center' }}>
              <div>
                <div style={{ display: 'flex', gap: 10, alignItems: 'baseline' }}>
                  <span style={{ fontFamily: 'var(--mono)', fontSize: 10.5, color: 'var(--cool)' }}>{d.technique}</span>
                  <span style={{ fontFamily: 'var(--sans)', fontSize: 14, color: 'var(--ink)', fontWeight: 500 }}>{d.title}</span>
                </div>
                <div style={{ fontFamily: 'var(--mono)', fontSize: 9.5, color: 'var(--ink-3)', textTransform: 'uppercase', letterSpacing: '0.14em', marginTop: 4 }}>
                  {d.kind} · {d.severity} · {d.source}
                </div>
              </div>
              <span style={{
                fontFamily: 'var(--mono)', fontSize: 10,
                color: sevColor(d.severity), border: `1px solid ${sevColor(d.severity)}`,
                padding: '4px 10px', textTransform: 'uppercase', letterSpacing: '0.14em',
              }}>{d.severity}</span>
            </div>
          ))}
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <a href="MayaTrail Playbook.html" style={{ textDecoration: 'none', display: 'block' }}>
            <EvCard
              name="playbook_AMBERSQUID.md"
              size="32 KB · 739 lines"
              desc="739-line IR playbook synthesized from this run's CloudTrail. Preparation, identification triggers (P0-P3), AWS CLI investigation queries, containment + eradication + recovery. Click to read →"
              clickable
            />
          </a>
          <EvCard name="detection-bundle.zip" size="18 KB" desc={`${shipped} Sigma rules with run-specific fixtures. Drop into your detection repo.`} />
          <EvCard name="cloudtrail.json" size="128 KB" desc="Raw CloudTrail dump. Hash-chained, sortable by run-id." />
          <EvCard name="mitre-map.svg"   size="14 KB"  desc="13 techniques across 6 tactics. Embeddable in any board report." />
          <a href="MayaTrail Coverage.html" style={{
            border: '1px solid var(--rule-2)', background: 'var(--bg-1)',
            padding: '14px 18px', textDecoration: 'none',
            display: 'flex', justifyContent: 'space-between', alignItems: 'center',
            fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--ink-2)',
            textTransform: 'uppercase', letterSpacing: '0.14em',
          }}>
            <span>See where this run sits in coverage →</span>
            <span style={{ color: 'var(--cool)' }}>32 techniques</span>
          </a>
        </div>
      </div>
    </div>
  );
}

function EvCard({ name, size, desc, clickable }) {
  return (
    <div style={{
      border: clickable ? '1px solid var(--cool)' : '1px solid var(--rule-2)',
      background: clickable ? 'linear-gradient(135deg, rgba(106,168,255,0.05), var(--bg-1) 60%)' : 'var(--bg-1)',
      transition: 'transform 0.15s, border-color 0.15s',
      cursor: clickable ? 'pointer' : 'default',
    }}
    onMouseEnter={clickable ? (e) => e.currentTarget.style.transform = 'translateY(-2px)' : undefined}
    onMouseLeave={clickable ? (e) => e.currentTarget.style.transform = 'none' : undefined}
    >
      <div style={{
        padding: '10px 14px', borderBottom: '1px solid var(--rule)', background: 'var(--bg-2)',
        display: 'flex', gap: 10, alignItems: 'center',
        fontFamily: 'var(--mono)', fontSize: 10.5, color: 'var(--ink-3)',
        textTransform: 'uppercase', letterSpacing: '0.14em',
      }}>
        <b style={{ color: clickable ? 'var(--cool)' : 'var(--ink)' }}>{name}</b>
        <span style={{ marginLeft: 'auto' }}>{size}</span>
      </div>
      <div style={{ padding: '14px 18px' }}>
        <div style={{ fontFamily: 'var(--sans)', fontSize: 12.5, color: 'var(--ink-2)', lineHeight: 1.5 }}>{desc}</div>
      </div>
    </div>
  );
}

/* ===========================================================
   APP
   =========================================================== */
function RunApp() {
  const [phase, setPhase] = useState('plan');
  const [result, setResult] = useState(null);

  return (
    <>
      {phase === 'plan' && <PlanView onRun={() => setPhase('running')} />}
      {phase === 'running' && <RunningView
        onComplete={(r) => { setResult(r); setPhase('complete'); }}
        onAbort={() => setPhase('plan')}
      />}
      {phase === 'complete' && result && <CompleteView result={result} onReset={() => setPhase('plan')} />}
    </>
  );
}

Object.assign(window, { RunApp });
