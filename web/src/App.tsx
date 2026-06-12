import React, { useState, useEffect } from 'react'
import axios from 'axios'
import './App.css'

interface Identity {
  id: string
  name: string
  kind: string
  provider: string
  risk_score: number
  state: string
}

interface Finding {
  id: string
  detector: string
  severity: string
  identity_id: string
  title: string
  narrative: string
  status: string
}

export default function App() {
  const [tab, setTab] = useState<'inventory' | 'triage' | 'settings'>('inventory')
  const [identities, setIdentities] = useState<Identity[]>([])
  const [findings, setFindings] = useState<Finding[]>([])
  const [loading, setLoading] = useState(false)
  const [selectedId, setSelectedId] = useState<string | null>(null)

  useEffect(() => {
    loadData()
  }, [tab])

  const loadData = async () => {
    setLoading(true)
    try {
      if (tab === 'inventory') {
        const res = await axios.get('/api/v1/identities')
        setIdentities(res.data.identities || [])
      } else if (tab === 'triage') {
        const res = await axios.get('/api/v1/triage')
        setIdentities(res.data.triage_queue || [])
        const findingsRes = await axios.get('/api/v1/findings')
        setFindings(findingsRes.data.findings || [])
      }
    } catch (err) {
      console.error('Load failed:', err)
    }
    setLoading(false)
  }

  return (
    <div className="app">
      <header className="header">
        <h1>🔐 NHIID</h1>
        <p>Non-Human Identity Inventory & Detection</p>
      </header>

      <nav className="nav">
        <button className={tab === 'inventory' ? 'active' : ''} onClick={() => setTab('inventory')}>
          📊 Inventory
        </button>
        <button className={tab === 'triage' ? 'active' : ''} onClick={() => setTab('triage')}>
          🚨 Triage
        </button>
        <button className={tab === 'settings' ? 'active' : ''} onClick={() => setTab('settings')}>
          ⚙️ Settings
        </button>
      </nav>

      <main className="main">
        {tab === 'inventory' && (
          <div>
            <h2>Identity Inventory</h2>
            {loading ? <p>Loading...</p> : (
              <table>
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Kind</th>
                    <th>Provider</th>
                    <th>State</th>
                    <th>Risk Score</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {identities.map(id => (
                    <tr key={id.id} onClick={() => setSelectedId(id.id)}>
                      <td><strong>{id.name}</strong></td>
                      <td>{id.kind}</td>
                      <td>{id.provider}</td>
                      <td>{id.state}</td>
                      <td className={`severity-${riskToSeverity(id.risk_score)}`}>{id.risk_score}</td>
                      <td><a href="#">View</a></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        )}

        {tab === 'triage' && (
          <div>
            <h2>Triage Queue</h2>
            {loading ? <p>Loading...</p> : (
              <div>
                <div className="findings-list">
                  {findings.length > 0 ? (
                    findings.slice(0, 10).map(f => (
                      <div key={f.id} className={`finding severity-${f.severity.toLowerCase()}`}>
                        <h3>{f.title}</h3>
                        <p>{f.narrative}</p>
                        <p><small>{f.detector} • Status: {f.status}</small></p>
                      </div>
                    ))
                  ) : (
                    <p>No findings. System is healthy! 🎉</p>
                  )}
                </div>
                <h3>Top-Risk Identities</h3>
                <table>
                  <thead>
                    <tr>
                      <th>Name</th>
                      <th>Risk</th>
                      <th>Findings</th>
                    </tr>
                  </thead>
                  <tbody>
                    {identities.slice(0, 10).map(id => (
                      <tr key={id.id}>
                        <td>{id.name}</td>
                        <td className={`severity-${riskToSeverity(id.risk_score)}`}>{id.risk_score}</td>
                        <td>{findings.filter(f => f.identity_id === id.id).length}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {tab === 'settings' && (
          <div>
            <h2>Settings</h2>
            <p>Configuration and API integration coming soon.</p>
          </div>
        )}
      </main>

      {selectedId && (
        <aside className="detail">
          <button onClick={() => setSelectedId(null)}>Close</button>
          <h3>Identity Detail (stub)</h3>
          <p>Detail view for {selectedId}</p>
        </aside>
      )}
    </div>
  )
}

function riskToSeverity(score: number): string {
  if (score >= 75) return 'critical'
  if (score >= 50) return 'high'
  if (score >= 25) return 'medium'
  return 'low'
}
