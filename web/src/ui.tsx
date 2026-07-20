// Small presentational building blocks shared across views: severity/risk badges, the risk ring
// and factor bars, provider/kind glyphs, and time/format helpers.
//
// Design note: colour here is reserved for the risk ramp only. Provider and kind are rendered
// achromatically (they are inventory facts, not risk signals) — see index.css.
import React from 'react'

// ----- severity / risk helpers -----

export type Sev = 'critical' | 'high' | 'medium' | 'low' | 'info'

export function riskSeverity(score: number): Sev {
  if (score >= 75) return 'critical'
  if (score >= 50) return 'high'
  if (score >= 25) return 'medium'
  return 'low'
}

export const sevLabel: Record<Sev, string> = {
  critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info',
}

export function SeverityPill({ sev }: { sev: string }) {
  const s = (sev || 'info').toLowerCase() as Sev
  return <span className={`pill pill-${s}`}>{sevLabel[s] ?? sev}</span>
}

export function RiskChip({ score }: { score: number }) {
  const sev = riskSeverity(score)
  return (
    <div className="risk-chip" title={`Risk ${score}`}>
      <span className={`risk-dot dot-${sev}`} />
      <span className="risk-num">{score}</span>
      <span className="risk-bar"><i className={`bar-${sev}`} style={{ width: `${Math.max(4, score)}%` }} /></span>
    </div>
  )
}

// Circular risk gauge for the detail drawer. Ticks every 9° (major every 45°) so the arc reads
// as an instrument dial rather than a progress bar.
export function RiskRing({ score }: { score: number }) {
  const sev = riskSeverity(score)
  const r = 46, c = 2 * Math.PI * r
  const clamped = Math.min(100, Math.max(0, score))
  const off = c - (clamped / 100) * c
  const ticks = Array.from({ length: 40 }, (_, i) => i)
  return (
    <div className="risk-ring">
      <svg width="120" height="120" viewBox="0 0 120 120" aria-hidden>
        <g className="ring-ticks">
          {ticks.map(i => (
            <line
              key={i}
              className={i % 5 === 0 ? 'maj' : undefined}
              x1="60" y1="3" x2="60" y2={i % 5 === 0 ? 9 : 6.5}
              transform={`rotate(${i * 9} 60 60)`}
            />
          ))}
        </g>
        <circle cx="60" cy="60" r={r} className="ring-track" />
        <circle cx="60" cy="60" r={r} className={`ring-val ring-${sev}`}
          strokeDasharray={c} strokeDashoffset={off} transform="rotate(-90 60 60)" />
      </svg>
      <div className="risk-ring-center">
        <span className="ring-score">{score}</span>
        <span className={`ring-sev sev-text-${sev}`}>{sevLabel[sev]}</span>
      </div>
    </div>
  )
}

// Horizontal bar for one risk factor with its contributing signals.
export function FactorBar({ name, score, signals }: { name: string; score: number; signals: string[] | null }) {
  const sev = riskSeverity(score)
  const label = name.replace(/_/g, ' ')
  return (
    <div className="factor">
      <div className="factor-head">
        <span className="factor-name">{label}</span>
        <span className="factor-score">{score}</span>
      </div>
      <div className="factor-track"><i className={`bar-${sev}`} style={{ width: `${Math.max(2, score)}%` }} /></div>
      {signals && signals.length > 0 && (
        <div className="factor-signals">
          {signals.map((s, i) => <span key={i} className="sig">{s.replace(/_/g, ' ')}</span>)}
        </div>
      )}
    </div>
  )
}

// ----- provider + kind glyphs -----

export function ProviderBadge({ provider }: { provider: string }) {
  const p = (provider || '').toLowerCase()
  const cls = p === 'aws' ? 'prov-aws' : p === 'gcp' ? 'prov-gcp' : p === 'github' ? 'prov-gh' : 'prov-other'
  return <span className={`prov ${cls}`}>{(provider || '—').toUpperCase()}</span>
}

// A typographic instrument code rather than an emoji — the inventory is machines, not faces.
export function KindGlyph({ kind, ai }: { kind: string; ai?: boolean }) {
  const code = ai ? 'AI'
    : kind?.includes('role') ? 'ROL'
    : kind?.includes('service_account') ? 'SVC'
    : kind?.includes('user') ? 'USR'
    : kind?.includes('workload') ? 'WKL'
    : 'ID'
  return <span className="kind-glyph" data-ai={ai ? '1' : undefined} title={kind}>{code}</span>
}

// ----- formatting -----

export function relTime(iso?: string | null): string {
  if (!iso) return 'never'
  const t = new Date(iso).getTime()
  if (Number.isNaN(t)) return '—'
  const diff = Date.now() - t
  if (diff < 0) return 'soon'
  const day = 86400000
  const d = Math.floor(diff / day)
  if (d === 0) return 'today'
  if (d === 1) return '1 day ago'
  if (d < 30) return `${d} days ago`
  if (d < 365) return `${Math.floor(d / 30)} mo ago`
  return `${Math.floor(d / 365)} yr ago`
}

export function shortKind(kind: string): string {
  return (kind || '').replace(/^aws_/, '').replace(/^gcp_/, '').replace(/_/g, ' ')
}

// ----- generic bits -----

export function Spinner({ label }: { label?: string }) {
  return <div className="spinner"><span className="spin" />{label && <span>{label}</span>}</div>
}

export function Empty({ icon = '✓', title, sub }: { icon?: string; title: string; sub?: string }) {
  return (
    <div className="empty">
      <div className="empty-icon">{icon}</div>
      <div className="empty-title">{title}</div>
      {sub && <div className="empty-sub">{sub}</div>}
    </div>
  )
}
