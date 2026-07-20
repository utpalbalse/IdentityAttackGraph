import React, { useEffect, useMemo, useState } from 'react'
import { api, Identity, Finding, IdentityDetail, AttackPath, Remediation } from './api'
import { GraphView } from './GraphView'
import {
  RiskChip, SeverityPill, RiskRing, FactorBar, ProviderBadge, KindGlyph,
  relTime, shortKind, riskSeverity, Spinner, Empty, Sev,
} from './ui'

type Tab = 'overview' | 'inventory' | 'graph' | 'triage'

export default function App() {
  const [tab, setTab] = useState<Tab>('overview')
  const [identities, setIdentities] = useState<Identity[]>([])
  const [findings, setFindings] = useState<Finding[]>([])
  const [riskReduced, setRiskReduced] = useState(0)
  const [loading, setLoading] = useState(true)
  const [online, setOnline] = useState<boolean | null>(null)
  const [selected, setSelected] = useState<string | null>(null)
  const [query, setQuery] = useState('')

  async function load() {
    setLoading(true)
    try {
      const [ids, fs, ok] = await Promise.all([api.identities(), api.findings(), api.health()])
      setIdentities(ids)
      setFindings(fs)
      setOnline(ok)
      api.riskReduction().then(r => setRiskReduced(r.risk_reduced)).catch(() => {})
    } catch {
      setOnline(false)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  const findingsByIdentity = useMemo(() => {
    const m: Record<string, Finding[]> = {}
    for (const f of findings) if (f.identity_id) (m[f.identity_id] ??= []).push(f)
    return m
  }, [findings])

  return (
    <div className="shell">
      <Sidebar tab={tab} setTab={setTab} online={online} counts={{ ids: identities.length, findings: findings.length }} />
      <main className="main">
        <Topbar tab={tab} query={query} setQuery={setQuery} onRefresh={load} loading={loading} />
        <div className="content">
          {loading ? <Spinner label="Loading inventory…" /> : (
            <>
              {tab === 'overview' && <Overview identities={identities} findings={findings} riskReduced={riskReduced} onOpen={setSelected} />}
              {tab === 'inventory' && <Inventory identities={identities} query={query} findingsByIdentity={findingsByIdentity} onOpen={setSelected} />}
              {tab === 'graph' && <GraphView onOpen={setSelected} findings={findings} />}
              {tab === 'triage' && <Triage identities={identities} findings={findings} onOpen={setSelected} />}
            </>
          )}
        </div>
      </main>
      {selected && <IdentityDrawer id={selected} onClose={() => setSelected(null)} />}
    </div>
  )
}

// ---------- sidebar ----------

function Sidebar({ tab, setTab, online, counts }: {
  tab: Tab; setTab: (t: Tab) => void; online: boolean | null; counts: { ids: number; findings: number }
}) {
  const items: { id: Tab; label: string; icon: string }[] = [
    { id: 'overview', label: 'Overview', icon: '◎' },
    { id: 'inventory', label: 'Inventory', icon: '▤' },
    { id: 'graph', label: 'Attack Graph', icon: '⬡' },
    { id: 'triage', label: 'Triage', icon: '⚑' },
  ]
  return (
    <aside className="sidebar">
      <div className="brand">
        <div className="brand-mark">⬡</div>
        <div className="brand-text">
          <div className="brand-name">IdentityAttackGraph</div>
          <div className="brand-sub">NHI Inventory &amp; Detection</div>
        </div>
      </div>
      <nav className="nav">
        {items.map(it => (
          <button key={it.id} className={`nav-item ${tab === it.id ? 'active' : ''}`} onClick={() => setTab(it.id)}>
            <span className="nav-icon">{it.icon}</span>
            <span>{it.label}</span>
            {it.id === 'triage' && counts.findings > 0 && <span className="nav-badge">{counts.findings}</span>}
          </button>
        ))}
      </nav>
      <div className="sidebar-foot">
        <div className="status">
          <span className={`status-dot ${online ? 'on' : online === false ? 'off' : ''}`} />
          {online === null ? 'connecting…' : online ? 'API connected' : 'API offline'}
        </div>
        <div className="foot-meta">{counts.ids} identities indexed</div>
      </div>
    </aside>
  )
}

// ---------- topbar ----------

function Topbar({ tab, query, setQuery, onRefresh, loading }: {
  tab: Tab; query: string; setQuery: (s: string) => void; onRefresh: () => void; loading: boolean
}) {
  const titles: Record<Tab, [string, string]> = {
    overview: ['Overview', 'Posture across your non-human identities'],
    inventory: ['Identity Inventory', 'Every machine identity, scored and searchable'],
    graph: ['Attack Graph', 'How identities reach roles, resources, and crown jewels'],
    triage: ['Triage Queue', 'Highest-urgency findings first'],
  }
  const [title, sub] = titles[tab]
  return (
    <header className="topbar">
      <div>
        <h1 className="page-title">{title}</h1>
        <p className="page-sub">{sub}</p>
      </div>
      <div className="topbar-actions">
        {tab === 'inventory' && (
          <div className="search">
            <span className="search-icon">⌕</span>
            <input value={query} onChange={e => setQuery(e.target.value)} placeholder="Search name, ARN, account…" />
          </div>
        )}
        <button className="btn-refresh" onClick={onRefresh} disabled={loading}>
          <span className={loading ? 'spin-inline' : ''}>↻</span> Refresh
        </button>
      </div>
    </header>
  )
}

// ---------- overview ----------

function Overview({ identities, findings, riskReduced, onOpen }: { identities: Identity[]; findings: Finding[]; riskReduced: number; onOpen: (id: string) => void }) {
  const stats = useMemo(() => {
    const sevCount: Record<Sev, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
    for (const i of identities) sevCount[riskSeverity(i.risk_score)]++
    return {
      total: identities.length,
      critical: sevCount.critical,
      high: sevCount.high,
      ai: identities.filter(i => i.is_ai_agent).length,
      findings: findings.filter(f => f.status === 'open').length,
      stale: identities.filter(i => relTime(i.last_seen_at) === 'never' || /yr|mo/.test(relTime(i.last_seen_at))).length,
    }
  }, [identities, findings])

  const top = useMemo(() => [...identities].sort((a, b) => b.risk_score - a.risk_score).slice(0, 6), [identities])
  const dist = useMemo(() => {
    const d: Record<Sev, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
    for (const i of identities) d[riskSeverity(i.risk_score)]++
    return d
  }, [identities])
  const max = Math.max(1, identities.length)

  if (identities.length === 0) {
    return <Empty icon="⌕" title="No identities yet" sub="Run a collector (fixture or AWS) to populate the inventory." />
  }

  return (
    <div className="stack">
      <div className="stat-grid">
        <Stat label="Total identities" value={stats.total} accent="accent" code="TOT" />
        <Stat label="Critical risk" value={stats.critical} accent="critical" code="CRT" />
        <Stat label="High risk" value={stats.high} accent="high" code="HGH" />
        <Stat label="Open findings" value={stats.findings} accent="med" code="OPN" />
        <Stat label="Risk reduced" value={riskReduced} accent="low" code="RDX" />
        <Stat label="AI agents" value={stats.ai} accent="accent2" code="AI" />
      </div>

      <div className="cols">
        <section className="card">
          <div className="card-head"><h2>Risk distribution</h2></div>
          <div className="dist">
            {(['critical', 'high', 'medium', 'low'] as Sev[]).map(s => (
              <div key={s} className="dist-row">
                <span className={`dist-label sev-text-${s}`}>{s}</span>
                <div className="dist-track"><i className={`bar-${s}`} style={{ width: `${(dist[s] / max) * 100}%` }} /></div>
                <span className="dist-count">{dist[s]}</span>
              </div>
            ))}
          </div>
        </section>

        <section className="card">
          <div className="card-head"><h2>Top risks</h2><span className="card-hint">click to inspect</span></div>
          <div className="toplist">
            {top.map(i => (
              <button key={i.id} className="toprow" onClick={() => onOpen(i.id)}>
                <KindGlyph kind={i.kind} ai={i.is_ai_agent} />
                <div className="toprow-main">
                  <span className="toprow-name">{i.name}</span>
                  <span className="toprow-sub">{shortKind(i.kind)} · {i.account_ref || i.provider}</span>
                </div>
                <RiskChip score={i.risk_score} />
              </button>
            ))}
          </div>
        </section>
      </div>
    </div>
  )
}

// An instrument readout: a mono channel code, the figure, then the human label.
function Stat({ label, value, accent, code }: { label: string; value: number; accent: string; code: string }) {
  return (
    <div className={`stat stat-${accent}`}>
      <div className="stat-code">{code}</div>
      <div className="stat-body">
        <div className="stat-value">{value}</div>
        <div className="stat-label">{label}</div>
      </div>
    </div>
  )
}

// ---------- inventory ----------

function Inventory({ identities, query, findingsByIdentity, onOpen }: {
  identities: Identity[]; query: string; findingsByIdentity: Record<string, Finding[]>; onOpen: (id: string) => void
}) {
  const [provider, setProvider] = useState('all')
  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    return identities
      .filter(i => provider === 'all' || i.provider === provider)
      .filter(i => !q || i.name.toLowerCase().includes(q) || (i.arn_or_email || '').toLowerCase().includes(q) || (i.account_ref || '').toLowerCase().includes(q))
      .sort((a, b) => b.risk_score - a.risk_score)
  }, [identities, query, provider])

  const providers = useMemo(() => ['all', ...Array.from(new Set(identities.map(i => i.provider)))], [identities])

  return (
    <div className="stack">
      <div className="filters">
        {providers.map(p => (
          <button key={p} className={`chip ${provider === p ? 'chip-on' : ''}`} onClick={() => setProvider(p)}>
            {p === 'all' ? 'All providers' : p.toUpperCase()}
          </button>
        ))}
        <span className="filter-count">{filtered.length} of {identities.length}</span>
      </div>

      {filtered.length === 0 ? <Empty icon="⌕" title="No matches" sub="Try a different search or filter." /> : (
        <div className="card table-card">
          <table className="grid">
            <thead>
              <tr>
                <th>Identity</th><th>Provider</th><th>Account</th>
                <th>Last seen</th><th>Findings</th><th className="ta-r">Risk</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map(i => {
                const fc = findingsByIdentity[i.id]?.length ?? 0
                return (
                  <tr key={i.id} onClick={() => onOpen(i.id)}>
                    <td>
                      <div className="cell-id">
                        <KindGlyph kind={i.kind} ai={i.is_ai_agent} />
                        <div>
                          <div className="cell-name">{i.name}{i.is_ai_agent && <span className="tag-ai">AI</span>}</div>
                          <div className="cell-arn">{i.arn_or_email || shortKind(i.kind)}</div>
                        </div>
                      </div>
                    </td>
                    <td><ProviderBadge provider={i.provider} /></td>
                    <td className="mono dim">{i.account_ref || '—'}</td>
                    <td className="dim">{relTime(i.last_seen_at)}</td>
                    <td>{fc > 0 ? <span className="fcount">{fc}</span> : <span className="dim">—</span>}</td>
                    <td className="ta-r"><RiskChip score={i.risk_score} /></td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

// ---------- triage ----------

function Triage({ identities, findings, onOpen }: { identities: Identity[]; findings: Finding[]; onOpen: (id: string) => void }) {
  const order: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 }
  const rank = (s: string) => order[(s || 'info').toLowerCase()] ?? 0
  const sorted = useMemo(() =>
    [...findings].sort((a, b) => rank(b.severity) - rank(a.severity) || b.confidence - a.confidence),
    [findings])
  const nameById = useMemo(() => Object.fromEntries(identities.map(i => [i.id, i.name])), [identities])

  return (
    <div className="stack">
      <div className="export-bar">
        <span className="export-label">Export findings</span>
        <a className="btn-export" href={api.exportFindings('sarif')} download>SARIF</a>
        <a className="btn-export" href={api.exportFindings('csv')} download>CSV</a>
        <a className="btn-export" href={api.exportFindings('json')} download>JSON</a>
        <a className="btn-export ghost" href={api.exportInventory('csv')} download>Inventory CSV</a>
      </div>
      {findings.length === 0 ? (
        <Empty title="No open findings" sub="Detectors found nothing actionable. Run the worker after collecting to evaluate detections." />
      ) : (
        <div className="findings">
          {sorted.map(f => (
            <button key={f.id} className={`finding sev-border-${(f.severity || 'info').toLowerCase()}`} onClick={() => { if (f.identity_id) onOpen(f.identity_id) }}>
              <div className="finding-top">
                <SeverityPill sev={f.severity} />
                <span className="finding-detector">{f.detector}</span>
                <span className="finding-conf">{f.confidence}% confidence</span>
              </div>
              <div className="finding-title">{f.title}</div>
              <div className="finding-narr">{f.narrative}</div>
              <div className="finding-foot">
                <span className="finding-subject">↳ {f.identity_id ? (nameById[f.identity_id] || f.identity_id.slice(0, 8)) : 'repository / secret (no owning identity)'}</span>
                <span className="finding-status">{f.status}</span>
              </div>
            </button>
          ))}
        </div>
      )}
    </div>
  )
}

// ---------- identity drawer ----------

function IdentityDrawer({ id, onClose }: { id: string; onClose: () => void }) {
  const [d, setD] = useState<IdentityDetail | null>(null)
  const [err, setErr] = useState<string | null>(null)

  useEffect(() => {
    setD(null); setErr(null)
    api.identity(id).then(setD).catch(e => setErr(String(e)))
  }, [id])

  useEffect(() => {
    const h = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', h)
    return () => window.removeEventListener('keydown', h)
  }, [onClose])

  return (
    <>
      <div className="overlay" onClick={onClose} />
      <aside className="drawer">
        {!d && !err && <Spinner label="Loading identity…" />}
        {err && <Empty icon="⚠" title="Could not load identity" sub={err} />}
        {d && <DrawerBody d={d} onClose={onClose} />}
      </aside>
    </>
  )
}

function DrawerBody({ d, onClose }: { d: IdentityDetail; onClose: () => void }) {
  const i = d.identity
  const factors = i.risk_breakdown || {}
  const factorOrder = ['privilege', 'blast_radius', 'exposure', 'trust', 'usage', 'freshness']
  const keys = factorOrder.filter(k => factors[k]).concat(Object.keys(factors).filter(k => !factorOrder.includes(k)))

  const [paths, setPaths] = useState<AttackPath[] | null>(null)
  useEffect(() => { api.attackPaths(i.id).then(setPaths).catch(() => setPaths([])) }, [i.id])

  const [rem, setRem] = useState<Remediation[]>(d.remediations || [])
  const remByFinding = useMemo(() => {
    const m: Record<string, Remediation[]> = {}
    for (const r of rem) (m[r.finding_id] ??= []).push(r)
    return m
  }, [rem])
  const markDone = async (id: string) => {
    if (await api.updateRemediation(id, 'done')) {
      setRem(rem.map(r => (r.id === id ? { ...r, status: 'done' } : r)))
    }
  }

  return (
    <div className="drawer-inner">
      <div className="drawer-head">
        <div className="drawer-id">
          <KindGlyph kind={i.kind} ai={i.is_ai_agent} />
          <div>
            <div className="drawer-name">{i.name}{i.is_ai_agent && <span className="tag-ai">AI</span>}</div>
            <div className="drawer-arn mono">{i.arn_or_email}</div>
          </div>
        </div>
        <button className="drawer-close" onClick={onClose}>✕</button>
      </div>

      <div className="drawer-scroll">
        <section className="risk-summary">
          <RiskRing score={i.risk_score} />
          <div className="risk-meta">
            <Meta k="Provider" v={<ProviderBadge provider={i.provider} />} />
            <Meta k="Kind" v={shortKind(i.kind)} />
            <Meta k="Account" v={<span className="mono">{i.account_ref || '—'}</span>} />
            <Meta k="State" v={<span className={`state state-${i.state}`}>{i.state}</span>} />
            <Meta k="Last seen" v={relTime(i.last_seen_at)} />
            <Meta k="Last rotated" v={relTime(i.last_rotated_at)} />
          </div>
        </section>

        {keys.length > 0 && (
          <section className="dsection">
            <h3>Risk breakdown</h3>
            <div className="factors">
              {keys.map(k => <FactorBar key={k} name={k} score={factors[k].score} signals={factors[k].signals} />)}
            </div>
          </section>
        )}

        {paths && paths.length > 0 && (
          <section className="dsection">
            <h3>Attack paths <span className="count-pill">{paths.length}</span></h3>
            <div className="paths">
              {paths.map(p => (
                <div key={p.rank} className="apath">
                  <div className="apath-head">
                    <span className={`pill pill-${p.impact === 'crown_jewel' ? 'critical' : 'high'}`}>{p.impact.replace(/_/g, ' ')}</span>
                    <span className="apath-hops">{p.hops} hop{p.hops === 1 ? '' : 's'}</span>
                  </div>
                  <div className="apath-chain">
                    {p.path.map((st, idx) => (
                      <React.Fragment key={idx}>
                        {idx > 0 && <span className="apath-via">{st.via?.replace(/_/g, ' ')} →</span>}
                        <span className={`apath-node node-${st.type} ${st.criticality === 'crown_jewel' ? 'node-crown' : ''}`}>{st.node}</span>
                      </React.Fragment>
                    ))}
                  </div>
                  <div className="apath-narr">{p.narrative}</div>
                </div>
              ))}
            </div>
          </section>
        )}

        {d.findings.length > 0 && (
          <section className="dsection">
            <h3>Open findings <span className="count-pill">{d.findings.length}</span></h3>
            <div className="dfindings">
              {d.findings.map(f => (
                <div key={f.id} className={`dfinding sev-border-${(f.severity || 'info').toLowerCase()}`}>
                  <div className="dfinding-top"><SeverityPill sev={f.severity} /><span className="finding-detector">{f.detector}</span></div>
                  <div className="dfinding-narr">{f.narrative}</div>
                  {(remByFinding[f.id] || []).length > 0 && (
                    <div className="remediations">
                      {remByFinding[f.id].map(rm => (
                        <div key={rm.id} className="remediation">
                          <div className="rem-head">
                            <span className="rem-action">{rm.action.replace(/_/g, ' ')}</span>
                            {rm.risk_delta > 0 && <span className="rem-delta">−{rm.risk_delta} risk</span>}
                            {rm.status === 'done'
                              ? <span className="rem-done">✓ done</span>
                              : <button className="rem-btn" onClick={() => markDone(rm.id)}>Mark done</button>}
                          </div>
                          {rm.notes && <div className="rem-rationale">{rm.notes}</div>}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </section>
        )}

        {d.credentials.length > 0 && (
          <section className="dsection">
            <h3>Credentials <span className="count-pill">{d.credentials.length}</span></h3>
            <div className="rows">
              {d.credentials.map(c => (
                <div key={c.id} className="row">
                  <span className="row-main mono">{c.external_id}</span>
                  <span className="row-tag">{c.cred_type.replace(/_/g, ' ')}</span>
                  <span className={`state state-${c.status === 'active' ? 'active' : 'disabled'}`}>{c.status}</span>
                  <span className="dim">{c.last_used_at ? `used ${relTime(c.last_used_at)}` : 'never used'}</span>
                </div>
              ))}
            </div>
          </section>
        )}

        {d.exposures.length > 0 && (
          <section className="dsection">
            <h3>Exposures <span className="count-pill">{d.exposures.length}</span></h3>
            <div className="rows">
              {d.exposures.map(e => (
                <div key={e.id} className="row">
                  <span className="row-main mono">{e.path}</span>
                  <span className="row-tag">{e.pattern}</span>
                  {e.verified && <span className="pill pill-critical">verified</span>}
                </div>
              ))}
            </div>
          </section>
        )}

        {d.trust_edges.length > 0 && (
          <section className="dsection">
            <h3>Trust relationships <span className="count-pill">{d.trust_edges.length}</span></h3>
            <div className="rows">
              {d.trust_edges.map(t => (
                <div key={t.id} className="row">
                  <span className="row-main">{t.edge_type.replace(/_/g, ' ')}</span>
                  <span className="dim">{t.observed ? 'observed' : 'policy-implied'}</span>
                </div>
              ))}
            </div>
          </section>
        )}
      </div>
    </div>
  )
}

function Meta({ k, v }: { k: string; v: React.ReactNode }) {
  return <div className="metarow"><span className="metak">{k}</span><span className="metav">{v}</span></div>
}
