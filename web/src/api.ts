// Typed client for the IdentityAttackGraph REST API. Uses fetch; the Vite dev server proxies
// /api to the Go backend (see vite.config.ts).

export interface Identity {
  id: string
  kind: string
  name: string
  arn_or_email: string
  provider: string
  account_ref?: string
  state: string
  risk_score: number
  is_ai_agent?: boolean
  last_seen_at?: string | null
  last_rotated_at?: string | null
  created_at_source?: string | null
  source?: string
  external_id?: string
  risk_breakdown?: Record<string, RiskFactor>
}

export interface RiskFactor {
  score: number
  signals: string[] | null
}

export interface Finding {
  id: string
  detector: string
  category: string
  severity: string
  confidence: number
  identity_id: string
  title: string
  narrative: string
  status: string
  evidence?: Record<string, unknown>
  first_seen_at?: string
  last_seen_at?: string
}

export interface Credential {
  id: string
  cred_type: string
  external_id: string
  status: string
  last_used_at?: string | null
  last_used_region?: string
  expires_at?: string | null
}

export interface TrustEdge {
  id: string
  edge_type: string
  observed: boolean
  condition?: Record<string, unknown>
}

export interface Exposure {
  id: string
  path: string
  pattern: string
  commit_sha?: string
  verified: boolean
}

export interface IdentityDetail {
  identity: Identity
  credentials: Credential[]
  roles: any[]
  resource_bindings: any[]
  trust_edges: TrustEdge[]
  workloads: any[]
  exposures: Exposure[]
  findings: Finding[]
  usage_sample: any[]
}

export interface PathStep {
  node: string
  type: string
  criticality?: string
  via?: string
}

export interface AttackPath {
  rank: number
  impact: string
  hops: number
  narrative: string
  path: PathStep[]
}

export interface GraphNode {
  id: string
  entity_id?: string
  type: string
  label: string
  criticality: string
}

export interface GraphEdge {
  id: string
  source: string
  target: string
  type: string
}

export interface GraphData {
  nodes: GraphNode[]
  edges: GraphEdge[]
}

const API = '/api/v1'

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${API}${path}`, { headers: { Accept: 'application/json' } })
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`)
  return res.json() as Promise<T>
}

export const api = {
  identities: () => get<{ identities: Identity[] }>('/identities').then(r => r.identities ?? []),
  triage: () => get<{ triage_queue: Identity[] }>('/triage').then(r => r.triage_queue ?? []),
  findings: () => get<{ findings: Finding[] }>('/findings').then(r => r.findings ?? []),
  identity: (id: string) => get<IdentityDetail>(`/identities/${id}`),
  attackPaths: (id: string) => get<{ paths: AttackPath[] }>(`/identities/${id}/attack-paths`).then(r => r.paths ?? []),
  graph: () => get<GraphData>('/graph'),
  health: () => fetch('/healthz').then(r => r.ok).catch(() => false),
}
