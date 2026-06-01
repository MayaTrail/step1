/**
 * Shared full-page background effects used on both LoginPage and ConnectorPage.
 *
 * AsciiArtBackground  — MITRE ATT&CK threat-feed text that scrolls upward
 *                       continuously at low opacity, acting as ambient texture.
 * FloatingDotsBackground — Red and green glowing dots that float upward,
 *                          distributed across the viewport via negative delays.
 */

const ASCII_ART = `
  MAYATRAIL — THREAT INTELLIGENCE FEED
  ─────────────────────────────────────────────────

  [CRIT]  T1486  Data Encrypted for Impact
  [HIGH]  T1078  Valid Accounts — IAM Role Abuse
  [HIGH]  T1537  Transfer Data to Cloud Account
  [MED]   T1136  Create Account
  [MED]   T1098  Account Manipulation
  [HIGH]  T1552  Unsecured Credentials
  [CRIT]  T1485  Data Destruction
  [MED]   T1087  Account Discovery
  [HIGH]  T1530  Data from Cloud Storage Object
  [LOW]   T1040  Network Sniffing
  [HIGH]  T1484  Domain Policy Modification
  [CRIT]  T1496  Resource Hijacking
  [MED]   T1562  Impair Defenses
  [HIGH]  T1021  Remote Services
  [LOW]   T1083  File and Directory Discovery
  [HIGH]  T1190  Exploit Public-Facing Application
  [MED]   T1059  Command and Scripting Interpreter
  [HIGH]  T1070  Indicator Removal on Host
  [MED]   T1018  Remote System Discovery
  [CRIT]  T1110  Brute Force — Password Spraying
  [HIGH]  T1114  Email Collection
  [MED]   T1057  Process Discovery
  [HIGH]  T1055  Process Injection
  [CRIT]  T1003  OS Credential Dumping

  ─────────────────────────────────────────────────
`

const PRE_STYLE: React.CSSProperties = {
  margin: 0,
  fontFamily: 'Geist Mono, monospace',
  fontSize: '11px',
  lineHeight: 1.95,
  color: '#FF6363',
  whiteSpace: 'pre',
  userSelect: 'none',
}

/**
 * MITRE ATT&CK threat-feed that scrolls upward continuously behind page content.
 * The art block is duplicated so the CSS loop is seamless — at -50% translateY
 * the second copy is pixel-aligned with where the first started.
 * The mask fades top/bottom edges so the scroll feels ambient rather than clipped.
 */
export function AsciiArtBackground() {
  return (
    <div
      className="absolute inset-0 overflow-hidden pointer-events-none"
      style={{
        zIndex: 1,
        maskImage: 'linear-gradient(to bottom, transparent 0%, black 18%, black 82%, transparent 100%)',
        WebkitMaskImage: 'linear-gradient(to bottom, transparent 0%, black 18%, black 82%, transparent 100%)',
      }}
    >
      <style>{`
        @keyframes mayatrail-ascii-scroll {
          from { transform: translateY(0); }
          to   { transform: translateY(-50%); }
        }
      `}</style>
      <div
        style={{
          opacity: 0.055,
          animation: 'mayatrail-ascii-scroll 38s linear infinite',
          willChange: 'transform',
        }}
      >
        <pre style={PRE_STYLE}>{ASCII_ART}</pre>
        {/* Duplicate — makes the scroll loop seamless */}
        <pre style={PRE_STYLE}>{ASCII_ART}</pre>
      </div>
    </div>
  )
}

const DOTS = [
  { id: 1,  x: 7,  size: 3, color: '#FF6363', duration: 9,  delay: 0    },
  { id: 2,  x: 18, size: 2, color: '#5fc992', duration: 12, delay: -4   },
  { id: 3,  x: 28, size: 4, color: '#FF6363', duration: 8,  delay: -7   },
  { id: 4,  x: 38, size: 2, color: '#5fc992', duration: 14, delay: -2   },
  { id: 5,  x: 47, size: 3, color: '#FF6363', duration: 10, delay: -9   },
  { id: 6,  x: 55, size: 2, color: '#5fc992', duration: 8,  delay: -5   },
  { id: 7,  x: 63, size: 4, color: '#FF6363', duration: 13, delay: -1   },
  { id: 8,  x: 72, size: 2, color: '#5fc992', duration: 9,  delay: -11  },
  { id: 9,  x: 82, size: 3, color: '#FF6363', duration: 11, delay: -6   },
  { id: 10, x: 91, size: 2, color: '#5fc992', duration: 8,  delay: -3   },
  { id: 11, x: 12, size: 2, color: '#5fc992', duration: 13, delay: -8   },
  { id: 12, x: 23, size: 3, color: '#FF6363', duration: 9,  delay: -12  },
  { id: 13, x: 34, size: 2, color: '#5fc992', duration: 11, delay: -3   },
  { id: 14, x: 44, size: 4, color: '#FF6363', duration: 8,  delay: -10  },
  { id: 15, x: 52, size: 2, color: '#5fc992', duration: 14, delay: -1   },
  { id: 16, x: 60, size: 3, color: '#FF6363', duration: 10, delay: -7   },
  { id: 17, x: 69, size: 2, color: '#5fc992', duration: 9,  delay: -4   },
  { id: 18, x: 78, size: 3, color: '#FF6363', duration: 12, delay: -13  },
  { id: 19, x: 87, size: 2, color: '#5fc992', duration: 8,  delay: -6   },
  { id: 20, x: 95, size: 3, color: '#FF6363', duration: 11, delay: -2   },
]

/**
 * Red (#FF6363) and green (#5fc992) glowing dots that rise from the bottom
 * and fade out at the top. Negative animationDelay pre-distributes them across
 * the full viewport height on page load so the screen is never empty.
 */
export function FloatingDotsBackground() {
  return (
    <div className="absolute inset-0 overflow-hidden pointer-events-none">
      <style>{`
        @keyframes mayatrail-float-l {
          0%   { transform: translateY(0)      translateX(0px);   opacity: 0; }
          12%  { opacity: 1; }
          50%  { transform: translateY(-55vh)  translateX(-10px); }
          88%  { opacity: 0.8; }
          100% { transform: translateY(-110vh) translateX(0px);   opacity: 0; }
        }
        @keyframes mayatrail-float-r {
          0%   { transform: translateY(0)      translateX(0px);  opacity: 0; }
          12%  { opacity: 1; }
          50%  { transform: translateY(-55vh)  translateX(10px); }
          88%  { opacity: 0.8; }
          100% { transform: translateY(-110vh) translateX(0px);  opacity: 0; }
        }
      `}</style>
      {DOTS.map((dot) => (
        <div
          key={dot.id}
          style={{
            position: 'absolute',
            left: `${dot.x}%`,
            bottom: '-6px',
            width: `${dot.size}px`,
            height: `${dot.size}px`,
            borderRadius: '50%',
            background: dot.color,
            boxShadow: `0 0 ${dot.size * 2}px ${dot.color}`,
            animation: `${dot.id % 2 === 0 ? 'mayatrail-float-r' : 'mayatrail-float-l'} ${dot.duration}s linear infinite`,
            animationDelay: `${dot.delay}s`,
          }}
        />
      ))}
    </div>
  )
}
