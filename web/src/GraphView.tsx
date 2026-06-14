import React, { useEffect, useRef, useState } from 'react'
import cytoscape from 'cytoscape'
import coseBilkent from 'cytoscape-cose-bilkent'
import { api, GraphData } from './api'
import { Spinner, Empty } from './ui'

// Register the layout extension once (guard against HMR double-registration).
try { cytoscape.use(coseBilkent) } catch { /* already registered */ }

const cyStyle = [
  {
    selector: 'node',
    style: {
      label: 'data(label)', color: '#cfd6e6', 'font-size': 9,
      'text-valign': 'bottom', 'text-margin-y': 5, 'text-max-width': 120,
      'text-wrap': 'ellipsis', width: 26, height: 26,
      'background-color': '#6d7cff', 'border-width': 2, 'border-color': '#2a3350',
    },
  },
  { selector: 'node[type="role"]', style: { 'background-color': '#fb923c', shape: 'round-rectangle', width: 30, height: 22 } },
  { selector: 'node[type="resource"]', style: { 'background-color': '#2dd4bf', shape: 'round-diamond', width: 30, height: 30 } },
  { selector: 'node[type="workload"]', style: { 'background-color': '#64748b', shape: 'round-rectangle' } },
  { selector: 'node[crit="crown_jewel"]', style: { 'background-color': '#f43f5e', 'border-color': '#ff8198', 'border-width': 3 } },
  { selector: 'node[crit="high"]', style: { 'border-color': '#fb923c', 'border-width': 3 } },
  { selector: 'node:selected', style: { 'border-color': '#fff', 'border-width': 3 } },
  {
    selector: 'edge',
    style: {
      width: 1.5, 'line-color': '#33405e', 'target-arrow-color': '#33405e',
      'target-arrow-shape': 'triangle', 'arrow-scale': 0.9, 'curve-style': 'bezier',
      label: 'data(label)', 'font-size': 8, color: '#7b85a3', 'text-rotation': 'autorotate',
      'text-background-color': '#0f1422', 'text-background-opacity': 1, 'text-background-padding': 2,
    },
  },
  { selector: 'edge[type="binds_to"]', style: { 'line-color': '#2dd4bf66', 'target-arrow-color': '#2dd4bf' } },
  { selector: 'edge[type="assumes"]', style: { 'line-color': '#fb923c66', 'target-arrow-color': '#fb923c' } },
]

const legend = [
  { c: '#6d7cff', label: 'Identity' },
  { c: '#fb923c', label: 'Role / permission set' },
  { c: '#2dd4bf', label: 'Resource' },
  { c: '#f43f5e', label: 'Crown jewel' },
  { c: '#64748b', label: 'Workload' },
]

export function GraphView({ onOpen }: { onOpen: (entityId: string) => void }) {
  const ref = useRef<HTMLDivElement>(null)
  const [data, setData] = useState<GraphData | null>(null)
  const [err, setErr] = useState<string | null>(null)

  useEffect(() => { api.graph().then(setData).catch(e => setErr(String(e))) }, [])

  useEffect(() => {
    if (!data || !ref.current || data.nodes.length === 0) return
    const cy = cytoscape({
      container: ref.current,
      elements: [
        ...data.nodes.map(n => ({ data: { id: n.id, label: n.label, type: n.type, crit: n.criticality, entity: n.entity_id } })),
        ...data.edges.map(e => ({ data: { id: e.id, source: e.source, target: e.target, label: e.type.replace(/_/g, ' '), type: e.type } })),
      ],
      style: cyStyle as any,
      layout: { name: 'cose-bilkent', animate: false, nodeDimensionsIncludeLabels: true, idealEdgeLength: 130, padding: 36 } as any,
      wheelSensitivity: 0.2,
      minZoom: 0.2,
      maxZoom: 2.5,
    })
    cy.on('tap', 'node', (evt: any) => {
      const d = evt.target.data()
      if (d.type === 'identity' && d.entity) onOpen(d.entity)
    })
    return () => cy.destroy()
  }, [data, onOpen])

  if (err) return <Empty icon="⚠" title="Could not load graph" sub={err} />
  if (!data) return <Spinner label="Loading attack graph…" />
  if (data.nodes.length === 0) {
    return <Empty icon="🕸" title="No graph yet" sub="Run a collector then the graph job to project the identity graph." />
  }

  return (
    <div className="graphwrap">
      <div className="graph-legend">
        {legend.map(l => (
          <span key={l.label} className="legend-item"><i style={{ background: l.c }} />{l.label}</span>
        ))}
        <span className="legend-hint">click an identity node to inspect · scroll to zoom · drag to pan</span>
      </div>
      <div className="cy" ref={ref} />
    </div>
  )
}
