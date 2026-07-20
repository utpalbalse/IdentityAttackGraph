import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import cytoscape from 'cytoscape'
import dagre from 'cytoscape-dagre'
import { api, Finding, GraphData, GraphNode } from './api'
import { Spinner, Empty } from './ui'

// Register the layout extension once (guard against HMR double-registration).
try { cytoscape.use(dagre) } catch { /* already registered */ }

/* ── Encoding ───────────────────────────────────────────────────────────────
   The console's global rule is "colour is risk". The attack graph is the one
   deliberate exception: here TYPE carries the hue (you need to read entity
   classes at a glance) and CRITICALITY is carried by the ring + glow, so crown
   jewels still read as the hottest thing on the canvas.

     hue        → what the entity is        (entry / compute / identity / role / data)
     ring+glow  → how critical it is        (crown jewel, high)
     line style → how the capability works  (dashed = privilege escalation,
                                             dotted = federated trust,
                                             solid red = the hop that lands on a crown jewel)
   ────────────────────────────────────────────────────────────────────────── */

const C = {
  external: '#fb7185', // rose   — internet-exposed entry point (leaked credential)
  compute: '#2dd4bf', // teal   — workloads / instances
  identity: '#818cf8', // indigo — IAM principals (users, service accounts, agents)
  role: '#fbbf24', // amber  — permission sets / roles
  data: '#38bdf8', // sky    — data stores & resources
  crown: '#ff2d46', // red    — crown-jewel criticality
  high: '#ff7a1a', // orange — high criticality
}

const INK = '#0b0908'
const CHIP = '#17130f'
const BONE = '#ece4d6'
const BONE_2 = '#a79e90'
const BONE_4 = '#4a443c'

// ── Lucide icons, inlined as data URIs (no external requests; CSP-safe) ──────
function lucide(body: string, color: string): string {
  const svg =
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="${color}" ` +
    `stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${body}</svg>`
  return 'data:image/svg+xml;utf8,' + encodeURIComponent(svg)
}

const PATHS = {
  // lucide: globe
  globe: '<circle cx="12" cy="12" r="10"/><path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20"/><path d="M2 12h20"/>',
  // lucide: server
  server: '<rect width="20" height="8" x="2" y="2" rx="2"/><rect width="20" height="8" x="2" y="14" rx="2"/><line x1="6" x2="6.01" y1="6" y2="6"/><line x1="6" x2="6.01" y1="18" y2="18"/>',
  // lucide: key-round
  key: '<path d="M2.586 17.414A2 2 0 0 0 2 18.828V21a1 1 0 0 0 1 1h3a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h1a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h.172a2 2 0 0 0 1.414-.586l.814-.814a6.5 6.5 0 1 0-4-4z"/><circle cx="16.5" cy="7.5" r=".5"/>',
  // lucide: shield
  shield: '<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/>',
  // lucide: database
  database: '<ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5V19A9 3 0 0 0 21 19V5"/><path d="M3 12A9 3 0 0 0 21 12"/>',
  // lucide: gem
  gem: '<path d="M6 3h12l4 6-10 13L2 9Z"/><path d="M11 3 8 9l4 13 4-13-3-6"/><path d="M2 9h20"/>',
}

type Cat = 'external' | 'compute' | 'identity' | 'role' | 'data' | 'crown'

const CAT_META: Record<Cat, { color: string; icon: string; label: string }> = {
  external: { color: C.external, icon: PATHS.globe, label: 'Exposed entry point' },
  compute: { color: C.compute, icon: PATHS.server, label: 'Compute / workload' },
  identity: { color: C.identity, icon: PATHS.key, label: 'Identity (IAM principal)' },
  role: { color: C.role, icon: PATHS.shield, label: 'Role / permission set' },
  data: { color: C.data, icon: PATHS.database, label: 'Data store / resource' },
  crown: { color: C.crown, icon: PATHS.gem, label: 'Crown jewel' },
}

/** Classify a graph node into its visual category. */
function categorize(n: GraphNode, exposed: Set<string>): Cat {
  if (n.type === 'resource') return n.criticality === 'crown_jewel' ? 'crown' : 'data'
  if (n.type === 'workload') return 'compute'
  if (n.type === 'role') return 'role'
  // An identity carrying a live credential exposure IS the external perimeter.
  if (n.entity_id && exposed.has(n.entity_id)) return 'external'
  return 'identity'
}

/** Shorten ARNs/URNs to the part a human actually reads; full value stays in the HUD. */
function short(label: string): string {
  if (!label) return ''
  let s = label
  if (s.startsWith('arn:aws:')) {
    const p = s.split(':')
    const svc = p[2] || ''
    const tail = p.slice(5).join(':') || p[p.length - 1]
    s = svc ? `${svc}:${tail}` : tail
  } else if (s.includes('.iam.gserviceaccount.com')) {
    s = s.split('@')[0]
  } else if (s.startsWith('gcp:')) {
    s = s.split(':').slice(-1)[0]
  } else if (s.startsWith('k8s://')) {
    s = s.replace('k8s://', '')
  }
  return s.length > 30 ? s.slice(0, 29) + '…' : s
}

const EDGE_META: Record<string, { label: string; color: string; dash: number[] | null }> = {
  assumes: { label: 'sts:AssumeRole — privilege escalation', color: C.role, dash: [7, 4] },
  impersonates: { label: 'impersonation — privilege escalation', color: C.role, dash: [7, 4] },
  federated_from: { label: 'federated trust (IRSA / WIF)', color: '#22d3ee', dash: [2, 4] },
  binds_to: { label: 'grants access to resource', color: C.data, dash: null },
  has_permissions: { label: 'holds permission set', color: '#6f6658', dash: null },
  uses: { label: 'workload runs as identity', color: C.compute, dash: null },
}

// ── stylesheet ───────────────────────────────────────────────────────────────
const cyStyle: any[] = [
  {
    selector: 'node',
    style: {
      shape: 'round-rectangle',
      'corner-radius': 13,
      width: 50,
      height: 50,
      'background-color': CHIP,
      'background-image': 'data(icon)',
      'background-fit': 'none',
      'background-width': '48%',
      'background-height': '48%',
      'background-position-x': '50%',
      'background-position-y': '50%',
      'background-clip': 'none',
      'border-width': 1.5,
      'border-color': 'data(color)',
      label: 'data(label)',
      color: BONE_2,
      'font-family': "'IBM Plex Mono', ui-monospace, monospace",
      'font-size': 10.5,
      'text-valign': 'bottom',
      'text-halign': 'center',
      'text-margin-y': 9,
      'text-max-width': 140,
      'text-wrap': 'ellipsis',
      'text-background-color': INK,
      'text-background-opacity': 0.82,
      'text-background-padding': 3,
      'text-background-shape': 'roundrectangle',
      'transition-property': 'opacity, border-width, underlay-opacity',
      'transition-duration': 160,
    },
  },
  // criticality: ring + soft glow (the "shadow"), never a hue swap
  {
    selector: 'node[crit="high"]',
    style: { 'border-width': 2, 'underlay-color': C.high, 'underlay-padding': 7, 'underlay-opacity': 0.14 },
  },
  {
    selector: 'node[cat="crown"]',
    style: {
      width: 62, height: 62, 'corner-radius': 16, 'border-width': 2.5,
      color: '#ff8b99', 'font-size': 10,
      'underlay-color': C.crown, 'underlay-padding': 11, 'underlay-opacity': 0.22,
    },
  },
  {
    selector: 'node[cat="external"]',
    style: { 'border-width': 2, 'underlay-color': C.external, 'underlay-padding': 9, 'underlay-opacity': 0.18 },
  },

  // ── edges ──
  {
    selector: 'edge',
    style: {
      width: 1.5,
      'line-color': 'data(color)',
      'target-arrow-color': 'data(color)',
      'target-arrow-shape': 'triangle',
      'arrow-scale': 0.95,
      'curve-style': 'bezier',
      opacity: 0.62,
      label: '', // edge labels are hover-only — always-on labels turn a graph into soup
      'font-family': "'IBM Plex Mono', ui-monospace, monospace",
      'font-size': 8.5,
      color: BONE_2,
      'text-background-color': INK,
      'text-background-opacity': 0.92,
      'text-background-padding': 3,
      'text-background-shape': 'roundrectangle',
      'text-rotation': 'autorotate',
      'transition-property': 'opacity, width',
      'transition-duration': 160,
    },
  },
  { selector: 'edge[dash]', style: { 'line-style': 'dashed', 'line-dash-pattern': 'data(dash)' } },
  // the payoff hop: a capability that lands directly on a crown jewel
  {
    selector: 'edge[toCrown = 1]',
    style: { 'line-color': C.crown, 'target-arrow-color': C.crown, width: 2.2, opacity: 0.85 },
  },

  // ── interaction states ──
  { selector: '.dimmed', style: { opacity: 0.07, 'underlay-opacity': 0, 'text-opacity': 0.05 } },
  {
    selector: 'node.focus',
    style: {
      'border-width': 3, 'border-color': BONE, color: BONE,
      'underlay-color': BONE, 'underlay-padding': 13, 'underlay-opacity': 0.2, 'z-index': 99,
    },
  },
  // upstream = how an attacker gets here
  {
    selector: 'node.up',
    style: { 'border-color': C.external, color: '#ffd0d8', 'underlay-color': C.external, 'underlay-padding': 9, 'underlay-opacity': 0.2 },
  },
  {
    selector: 'edge.up',
    style: { 'line-color': C.external, 'target-arrow-color': C.external, width: 2.6, opacity: 1, label: 'data(label)', 'z-index': 98 },
  },
  // downstream = what falls if this is owned
  {
    selector: 'node.down',
    style: { 'border-color': C.high, color: '#ffd7b0', 'underlay-color': C.high, 'underlay-padding': 9, 'underlay-opacity': 0.2 },
  },
  {
    selector: 'edge.down',
    style: { 'line-color': C.high, 'target-arrow-color': C.high, width: 2.6, opacity: 1, label: 'data(label)', 'z-index': 98 },
  },
  { selector: 'node:selected', style: { 'border-color': BONE, 'border-width': 3 } },
]

type Dir = 'LR' | 'TB'

interface Hud {
  label: string
  cat: Cat
  crit: string
  up: number
  down: number
  clickable: boolean
  side: 'left' | 'right' // flips away from the hovered node so the read-out never covers it
}

export function GraphView({ onOpen, findings }: { onOpen: (entityId: string) => void; findings: Finding[] }) {
  const ref = useRef<HTMLDivElement>(null)
  const cyRef = useRef<any>(null)
  const [data, setData] = useState<GraphData | null>(null)
  const [err, setErr] = useState<string | null>(null)
  const [dir, setDir] = useState<Dir>('LR')
  const [crownOnly, setCrownOnly] = useState(false)
  const [hud, setHud] = useState<Hud | null>(null)

  useEffect(() => { api.graph().then(setData).catch(e => setErr(String(e))) }, [])

  // Identities with a live credential exposure are the graph's external perimeter.
  const exposed = useMemo(() => {
    const s = new Set<string>()
    for (const f of findings) {
      if (f.identity_id && (f.category === 'exposure' || f.detector === 'secret_exposed_in_repo')) {
        s.add(f.identity_id)
      }
    }
    return s
  }, [findings])

  const elements = useMemo(() => {
    if (!data) return null
    const catOf = new Map<string, Cat>()
    for (const n of data.nodes) catOf.set(n.id, categorize(n, exposed))

    let nodes = data.nodes
    let edges = data.edges

    // "Crown-jewel paths only": keep crown jewels and everything that can reach them.
    if (crownOnly) {
      const incoming = new Map<string, string[]>()
      for (const e of edges) {
        const arr = incoming.get(e.target) || []
        arr.push(e.source)
        incoming.set(e.target, arr)
      }
      const keep = new Set<string>()
      const stack = data.nodes.filter(n => catOf.get(n.id) === 'crown').map(n => n.id)
      for (const id of stack) keep.add(id)
      while (stack.length) {
        const cur = stack.pop()!
        for (const src of incoming.get(cur) || []) {
          if (!keep.has(src)) { keep.add(src); stack.push(src) }
        }
      }
      nodes = nodes.filter(n => keep.has(n.id))
      edges = edges.filter(e => keep.has(e.source) && keep.has(e.target))
    }

    return [
      ...nodes.map(n => {
        const cat = catOf.get(n.id)!
        const meta = CAT_META[cat]
        return {
          data: {
            id: n.id,
            label: short(n.label),
            full: n.label,
            type: n.type,
            cat,
            crit: n.criticality || 'low',
            entity: n.entity_id,
            color: meta.color,
            icon: lucide(meta.icon, meta.color),
          },
        }
      }),
      ...edges.map(e => {
        const meta = EDGE_META[e.type] || { label: e.type.replace(/_/g, ' '), color: BONE_4, dash: null }
        return {
          data: {
            id: e.id,
            source: e.source,
            target: e.target,
            label: meta.label,
            type: e.type,
            color: meta.color,
            ...(meta.dash ? { dash: meta.dash } : {}),
            toCrown: catOf.get(e.target) === 'crown' ? 1 : 0,
          },
        }
      }),
    ]
  }, [data, exposed, crownOnly])

  /**
   * dagre lays out each weakly-connected component well but stacks them along one axis, so a
   * graph of many shallow chains ends up a tall ribbon with most of the panel empty. Shelf-pack
   * the components to roughly the panel's aspect ratio; flow *within* a component is untouched.
   */
  const packComponents = useCallback((cy: any, aspect: number) => {
    const comps: any[] = cy.elements().components()
    if (comps.length < 2) return
    const gap = 62
    const boxes = comps
      .map((c: any) => ({ c, bb: c.boundingBox({ includeLabels: true }) }))
      .sort((a: any, b: any) => b.bb.h - a.bb.h) // tallest first packs tighter
    const area = boxes.reduce((s: number, b: any) => s + b.bb.w * b.bb.h, 0)
    const targetW = Math.max(
      Math.max(...boxes.map((b: any) => b.bb.w)),
      Math.sqrt(area * Math.max(aspect, 0.2)),
    )
    let x = 0, y = 0, rowH = 0
    for (const b of boxes) {
      if (x > 0 && x + b.bb.w > targetW) { x = 0; y += rowH + gap; rowH = 0 }
      const dx = x - b.bb.x1
      const dy = y - b.bb.y1
      b.c.nodes().positions((n: any) => {
        const p = n.position()
        return { x: p.x + dx, y: p.y + dy }
      })
      x += b.bb.w + gap
      rowH = Math.max(rowH, b.bb.h)
    }
  }, [])

  const runLayout = useCallback((cy: any, direction: Dir) => {
    const l = cy.layout({
      name: 'dagre',
      rankDir: direction,
      // generous separation + label-aware sizing is what actually prevents overlap
      nodeSep: direction === 'LR' ? 58 : 78,
      edgeSep: 28,
      rankSep: direction === 'LR' ? 150 : 120,
      ranker: 'network-simplex',
      nodeDimensionsIncludeLabels: true,
      animate: false,
      fit: false,
      padding: 40,
    })
    // Fit only once the container has its final flex-resolved size, otherwise the viewport is
    // measured mid-layout and the graph renders tiny in a sea of empty canvas.
    l.one('layoutstop', () => {
      requestAnimationFrame(() => {
        cy.resize()
        const ext = cy.extent()
        packComponents(cy, Math.max(1, ext.w) / Math.max(1, ext.h))
        cy.fit(undefined, 40)
      })
    })
    l.run()
  }, [packComponents])

  useEffect(() => {
    if (!elements || !ref.current || elements.length === 0) return
    const cy = cytoscape({
      container: ref.current,
      elements,
      style: cyStyle,
      wheelSensitivity: 0.22,
      minZoom: 0.15,
      maxZoom: 2.8,
    })
    cyRef.current = cy

    // Labels participate in layout (nodeDimensionsIncludeLabels), and label widths depend on the
    // webfont. Laying out before IBM Plex Mono loads measures fallback metrics, so the graph
    // re-flows — and can overlap — once the font swaps in. Wait for fonts, then lay out once.
    let cancelled = false
    const start = () => { if (!cancelled) runLayout(cy, dir) }
    const fonts = (document as any).fonts
    if (fonts?.ready) fonts.ready.then(start).catch(start)
    else start()

    const clear = () => {
      cy.elements().removeClass('dimmed up down focus')
      setHud(null)
      if (ref.current) ref.current.style.cursor = 'default'
    }

    cy.on('mouseover', 'node', (evt: any) => {
      const n = evt.target
      const up = n.predecessors()   // every route an attacker can take to reach this node
      const down = n.successors()   // everything that falls if this node is owned
      cy.elements().addClass('dimmed')
      up.removeClass('dimmed').addClass('up')
      down.removeClass('dimmed').addClass('down')
      n.removeClass('dimmed').addClass('focus')
      const d = n.data()
      const rp = n.renderedPosition()
      setHud({
        label: d.full,
        cat: d.cat,
        crit: d.crit,
        up: up.nodes().length,
        down: down.nodes().length,
        clickable: d.type === 'identity' && !!d.entity,
        side: rp.x < cy.width() / 2 ? 'right' : 'left',
      })
      if (ref.current) ref.current.style.cursor = d.type === 'identity' && d.entity ? 'pointer' : 'default'
    })
    cy.on('mouseout', 'node', clear)
    cy.on('tap', (evt: any) => { if (evt.target === cy) clear() })

    cy.on('tap', 'node', (evt: any) => {
      const d = evt.target.data()
      if (d.type === 'identity' && d.entity) onOpen(d.entity)
    })

    // keep the projection filling its panel when the window/sidebar changes
    const ro = new ResizeObserver(() => { cy.resize(); cy.fit(undefined, 40) })
    ro.observe(ref.current)

    return () => { cancelled = true; ro.disconnect(); cy.destroy(); cyRef.current = null }
  }, [elements, dir, runLayout, onOpen])

  if (err) return <Empty icon="⚠" title="Could not load graph" sub={err} />
  if (!data) return <Spinner label="Loading attack graph…" />
  if (data.nodes.length === 0) {
    return <Empty icon="⬡" title="No graph yet" sub="Run a collector then the graph job to project the identity graph." />
  }

  const legendCats: Cat[] = ['external', 'compute', 'identity', 'role', 'data', 'crown']

  return (
    <div className="graphwrap">
      <div className="graph-toolbar">
        <div className="legend-row">
          <span className="legend-group-label">entities</span>
          {legendCats.map(c => (
            <span key={c} className="legend-item" title={CAT_META[c].label}>
              <i className="lg-chip" style={{ borderColor: CAT_META[c].color }}>
                <img src={lucide(CAT_META[c].icon, CAT_META[c].color)} alt="" width={11} height={11} />
              </i>
              {CAT_META[c].label}
            </span>
          ))}
        </div>
        <div className="legend-row">
          <span className="legend-group-label">capabilities</span>
          <span className="legend-item"><i className="lg-line dash" style={{ background: C.role }} />privilege escalation (assume / impersonate)</span>
          <span className="legend-item"><i className="lg-line dot" style={{ background: '#22d3ee' }} />federated trust (IRSA / WIF)</span>
          <span className="legend-item"><i className="lg-line" style={{ background: C.data }} />resource access</span>
          <span className="legend-item"><i className="lg-line" style={{ background: C.crown }} />reaches a crown jewel</span>
          <div className="graph-controls">
            <button className={`gbtn ${crownOnly ? 'gbtn-on' : ''}`} onClick={() => setCrownOnly(v => !v)}
              title="Show only nodes on a path to a crown jewel">
              Crown-jewel paths
            </button>
            <button className="gbtn" onClick={() => setDir(d => (d === 'LR' ? 'TB' : 'LR'))}
              title="Toggle layout direction">
              {dir === 'LR' ? 'Left → right' : 'Top → down'}
            </button>
            <button className="gbtn" onClick={() => cyRef.current?.fit(undefined, 52)} title="Fit graph to view">Fit</button>
          </div>
        </div>
      </div>

      <div className="cy-wrap">
        <div className="cy" ref={ref} />
        {hud ? (
          <div className={`graph-hud side-${hud.side}`}>
            <div className="hud-top">
              <i className="lg-chip" style={{ borderColor: CAT_META[hud.cat].color }}>
                <img src={lucide(CAT_META[hud.cat].icon, CAT_META[hud.cat].color)} alt="" width={11} height={11} />
              </i>
              <span className="hud-cat" style={{ color: CAT_META[hud.cat].color }}>{CAT_META[hud.cat].label}</span>
              {hud.crit && hud.crit !== 'low' && (
                <span className={`hud-crit crit-${hud.crit}`}>{hud.crit.replace(/_/g, ' ')}</span>
              )}
            </div>
            <div className="hud-label">{hud.label}</div>
            <div className="hud-stats">
              <span><b style={{ color: C.external }}>{hud.up}</b> upstream — can reach this</span>
              <span><b style={{ color: C.high }}>{hud.down}</b> downstream — blast radius</span>
            </div>
            {hud.clickable && <div className="hud-hint">click to inspect this identity</div>}
          </div>
        ) : (
          <div className="graph-hint">hover a node to trace its attack path and blast radius · click an identity to inspect · scroll to zoom</div>
        )}
      </div>
    </div>
  )
}
