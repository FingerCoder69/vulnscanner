import { useState, useRef, useCallback } from 'react'
import ScanForm from './components/ScanForm'
import Terminal from './components/Terminal'
import PortCard from './components/PortCard'
import SummaryBar from './components/SummaryBar'
import DASTForm from './components/DASTForm'
import DASTFindingCard from './components/DASTFindingCard'
import AIReport from './components/AIReport'

const WS_URL = import.meta.env.VITE_WS_URL || 'ws://localhost:8000/ws/scan'
const DAST_WS_URL = import.meta.env.VITE_DAST_WS_URL || 'ws://localhost:8000/ws/dast'

export default function App() {
  const [activeTab, setActiveTab] = useState('network') // 'network' | 'dast'

  // ── Network scanner state ──
  const [scanning, setScanning] = useState(false)
  const [logs, setLogs] = useState([])
  const [results, setResults] = useState(null)
  const [error, setError] = useState(null)
  const [livePorts, setLivePorts] = useState([])
  const wsRef = useRef(null)

  // ── DAST state ──
  const [dastScanning, setDastScanning] = useState(false)
  const [dastLogs, setDastLogs] = useState([])
  const [dastResults, setDastResults] = useState(null)
  const [dastError, setDastError] = useState(null)
  const dastWsRef = useRef(null)

  const addLog = useCallback((msg) => setLogs(prev => [...prev, msg]), [])
  const addDastLog = useCallback((msg) => setDastLogs(prev => [...prev, msg]), [])

  // ── Network scanner ──
  const startScan = useCallback((params) => {
    if (wsRef.current) wsRef.current.close()
    setScanning(true); setLogs([]); setResults(null); setError(null); setLivePorts([])

    const ws = new WebSocket(WS_URL)
    wsRef.current = ws

    ws.onopen = () => ws.send(JSON.stringify(params))
    ws.onmessage = (e) => {
      const msg = JSON.parse(e.data)
      if (msg.event === 'start') {
        addLog(`[*] Scan ID: ${msg.scan_id}`)
        addLog(`[*] Target: ${msg.target}`)
        addLog(`[*] Port range: ${msg.port_range}`)
      } else if (msg.event === 'log') {
        addLog(msg.message)
      } else if (msg.event === 'port_found') {
        setLivePorts(prev => [...prev, msg.port])
        addLog(`[+] Open port detected: ${msg.port}`)
      } else if (msg.event === 'done') {
        setResults(msg); setScanning(false); addLog('[+] Pipeline complete.')
      } else if (msg.event === 'error') {
        setError(msg.message); addLog(`[!] Error: ${msg.message}`); setScanning(false)
      }
    }
    ws.onerror = () => {
      setError('WebSocket connection failed. Is the backend running?')
      addLog('[!] Connection error.'); setScanning(false)
    }
    ws.onclose = () => { if (scanning) addLog('[*] Connection closed.') }
  }, [addLog])

  // ── DAST scanner ──
  const startDast = useCallback((params) => {
    if (dastWsRef.current) dastWsRef.current.close()
    setDastScanning(true); setDastLogs([]); setDastResults(null); setDastError(null)

    const ws = new WebSocket(DAST_WS_URL)
    dastWsRef.current = ws

    ws.onopen = () => ws.send(JSON.stringify(params))
    ws.onmessage = (e) => {
      const msg = JSON.parse(e.data)
      if (msg.event === 'start') {
        addDastLog(`[*] Scan ID: ${msg.scan_id}`)
        addDastLog(`[*] Target: ${msg.target}`)
      } else if (msg.event === 'log') {
        addDastLog(msg.message)
      } else if (msg.event === 'finding') {
        addDastLog(msg.message)
      } else if (msg.event === 'finding_ai') {
        addDastLog(`  [AI ✓] ${msg.check} triaged`)
      } else if (msg.event === 'done') {
        setDastResults(msg); setDastScanning(false); addDastLog('[+] DAST complete.')
      } else if (msg.event === 'error') {
        setDastError(msg.message); addDastLog(`[!] ${msg.message}`); setDastScanning(false)
      }
    }
    ws.onerror = () => {
      setDastError('WebSocket connection failed.')
      addDastLog('[!] Connection error.'); setDastScanning(false)
    }
  }, [addDastLog])

  const tabs = [
    { id: 'network', label: 'Network Scanner', icon: '⬡', desc: 'Port scan + CVE lookup' },
    { id: 'dast',    label: 'DAST + AI',        icon: '⚡', desc: 'Web app attack surface' },
  ]

  return (
    <div style={styles.root}>
      {/* Header */}
      <header style={styles.header}>
        <div style={styles.headerInner}>
          <div style={styles.logo}>
            <span style={styles.logoIcon}>⬡</span>
            <span style={styles.logoText}>VulnScanner</span>
            <span style={styles.logoBadge}>v2.0</span>
          </div>
          <div style={styles.headerRight}>
            <span style={styles.statusDot} />
            <span style={styles.statusText}>READY</span>
          </div>
        </div>
      </header>

      {/* Tab bar */}
      <div style={styles.tabBar}>
        <div style={styles.tabBarInner}>
          {tabs.map(tab => (
            <button
              key={tab.id}
              style={activeTab === tab.id ? styles.tabActive : styles.tab}
              onClick={() => setActiveTab(tab.id)}
            >
              <span style={styles.tabIcon}>{tab.icon}</span>
              <div style={styles.tabContent}>
                <span style={styles.tabLabel}>{tab.label}</span>
                <span style={styles.tabDesc}>{tab.desc}</span>
              </div>
              {tab.id === 'dast' && (
                <span style={styles.newTag}>AI</span>
              )}
            </button>
          ))}
        </div>
      </div>

      <main style={styles.main}>

        {/* ── Network Scanner tab ── */}
        {activeTab === 'network' && (
          <>
            {livePorts.length > 0 && scanning && (
              <div style={styles.ticker}>
                <span style={styles.tickerLabel}>LIVE ▶</span>
                {livePorts.slice(-12).map(p => (
                  <span key={p} style={styles.tickerPort}>{p}</span>
                ))}
              </div>
            )}
            <ScanForm onScan={startScan} scanning={scanning} />
            {error && <div style={styles.errorBox}><span style={styles.errorText}>[!] {error}</span></div>}
            <Terminal lines={logs} visible={logs.length > 0} />
            {results && (
              <>
                <SummaryBar data={results} />
                <div style={styles.findingsHeader}>
                  <h2 style={styles.findingsTitle}>Findings</h2>
                  <span style={styles.findingsCount}>{results.results.length} port{results.results.length !== 1 ? 's' : ''}</span>
                </div>
                {results.results.length === 0
                  ? <p style={styles.empty}>No open ports found in the specified range.</p>
                  : results.results.map(entry => <PortCard key={entry.port} entry={entry} />)
                }
              </>
            )}
          </>
        )}

        {/* ── DAST tab ── */}
        {activeTab === 'dast' && (
          <>
            <DASTForm onScan={startDast} scanning={dastScanning} />
            {dastError && <div style={styles.errorBox}><span style={styles.errorText}>[!] {dastError}</span></div>}
            <Terminal lines={dastLogs} visible={dastLogs.length > 0} />
            {dastResults && (
              <>
                {/* DAST summary bar */}
                <div style={styles.dastSummary}>
                  <div style={styles.dastMeta}>
                    <span style={styles.dastTarget}>{dastResults.target}</span>
                    <span style={styles.sep}>·</span>
                    <span style={styles.dastDim}>{new Date(dastResults.timestamp).toLocaleTimeString()}</span>
                  </div>
                  <div style={styles.dastStats}>
                    <DastStat label="TOTAL" value={dastResults.stats?.total || 0} color="var(--text)" />
                    <DastStat label="CRITICAL" value={dastResults.stats?.critical || 0} color="#ff4d4d" />
                    <DastStat label="HIGH" value={dastResults.stats?.high || 0} color="#ffb740" />
                    <DastStat label="MEDIUM" value={dastResults.stats?.medium || 0} color="#4da6ff" />
                    <DastStat label="LOW" value={dastResults.stats?.low || 0} color="var(--green)" />
                  </div>
                  {dastResults.params_tested?.length > 0 && (
                    <div style={styles.paramsRow}>
                      <span style={styles.paramsLabel}>PARAMS TESTED:</span>
                      {dastResults.params_tested.map(p => (
                        <span key={p} style={styles.paramTag}>{p}</span>
                      ))}
                    </div>
                  )}
                </div>

                {/* AI Report */}
                {dastResults.ai_report && <AIReport report={dastResults.ai_report} />}

                {/* Findings */}
                <div style={styles.findingsHeader}>
                  <h2 style={styles.findingsTitle}>Findings</h2>
                  <span style={styles.findingsCount}>{dastResults.findings?.length || 0} issue{dastResults.findings?.length !== 1 ? 's' : ''}</span>
                </div>
                {!dastResults.findings || dastResults.findings.length === 0
                  ? <p style={styles.empty}>No vulnerabilities found. Target may be well-hardened or dynamic testing was limited.</p>
                  : dastResults.findings.map((f, i) => <DASTFindingCard key={i} finding={f} index={i} />)
                }
              </>
            )}
          </>
        )}
      </main>

      <footer style={styles.footer}>
        For authorized use only &nbsp;·&nbsp; Built with Python + FastAPI + React + Claude AI
      </footer>

      <style>{`
        @keyframes spin { to { transform: rotate(360deg); } }
        @keyframes blink { 0%, 100% { opacity: 1; } 50% { opacity: 0; } }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: none; } }
        input:focus { border-color: var(--green) !important; }
        button:not(:disabled):hover { opacity: 0.85; }
      `}</style>
    </div>
  )
}

function DastStat({ label, value, color }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
      <span style={{ fontFamily: 'var(--mono)', fontSize: 28, fontWeight: 700, color, lineHeight: 1 }}>{value}</span>
      <span style={{ fontFamily: 'var(--mono)', fontSize: 9, letterSpacing: '0.12em', color: 'var(--text-dim)', fontWeight: 700 }}>{label}</span>
    </div>
  )
}

const styles = {
  root: { minHeight: '100vh', display: 'flex', flexDirection: 'column' },
  header: { borderBottom: '1px solid var(--border)', background: 'var(--bg2)', position: 'sticky', top: 0, zIndex: 10 },
  headerInner: { maxWidth: 960, margin: '0 auto', padding: '14px 24px', display: 'flex', alignItems: 'center', justifyContent: 'space-between' },
  logo: { display: 'flex', alignItems: 'center', gap: 10 },
  logoIcon: { fontSize: 18, color: 'var(--green)' },
  logoText: { fontFamily: 'var(--mono)', fontSize: 15, fontWeight: 700, color: 'var(--text)', letterSpacing: '0.05em' },
  logoBadge: { fontFamily: 'var(--mono)', fontSize: 9, color: 'var(--green)', background: 'var(--green-bg)', border: '1px solid rgba(0,255,136,0.2)', borderRadius: 4, padding: '2px 6px', letterSpacing: '0.1em' },
  headerRight: { display: 'flex', alignItems: 'center', gap: 8 },
  statusDot: { width: 8, height: 8, borderRadius: '50%', background: 'var(--green)', boxShadow: '0 0 6px var(--green)' },
  statusText: { fontFamily: 'var(--mono)', fontSize: 10, color: 'var(--green)', letterSpacing: '0.1em' },
  tabBar: { borderBottom: '1px solid var(--border)', background: 'var(--bg2)' },
  tabBarInner: { maxWidth: 960, margin: '0 auto', padding: '0 24px', display: 'flex', gap: 4 },
  tab: {
    display: 'flex', alignItems: 'center', gap: 10,
    padding: '14px 20px', background: 'transparent',
    border: 'none', borderBottom: '2px solid transparent',
    cursor: 'pointer', color: 'var(--text-dim)',
    transition: 'all 0.15s', marginBottom: -1,
  },
  tabActive: {
    display: 'flex', alignItems: 'center', gap: 10,
    padding: '14px 20px', background: 'transparent',
    border: 'none', borderBottom: '2px solid var(--green)',
    cursor: 'pointer', color: 'var(--text)',
    transition: 'all 0.15s', marginBottom: -1,
  },
  tabIcon: { fontSize: 16, color: 'var(--green)' },
  tabContent: { display: 'flex', flexDirection: 'column', alignItems: 'flex-start', gap: 1 },
  tabLabel: { fontFamily: 'var(--mono)', fontSize: 12, fontWeight: 700, letterSpacing: '0.05em' },
  tabDesc: { fontFamily: 'var(--mono)', fontSize: 9, color: 'var(--text-dim)', letterSpacing: '0.05em' },
  newTag: { fontFamily: 'var(--mono)', fontSize: 8, fontWeight: 700, color: 'var(--green)', background: 'var(--green-bg)', border: '1px solid rgba(0,255,136,0.2)', borderRadius: 3, padding: '1px 5px', letterSpacing: '0.08em' },
  main: { flex: 1, maxWidth: 960, margin: '0 auto', width: '100%', padding: '32px 24px' },
  ticker: { background: 'var(--bg2)', border: '1px solid rgba(0,255,136,0.2)', borderRadius: 8, padding: '8px 16px', marginBottom: 16, display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', animation: 'fadeIn 0.3s ease' },
  tickerLabel: { fontFamily: 'var(--mono)', fontSize: 10, color: 'var(--green)', fontWeight: 700, letterSpacing: '0.1em' },
  tickerPort: { fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--green-dim)', background: 'var(--green-bg)', border: '1px solid rgba(0,255,136,0.15)', borderRadius: 4, padding: '2px 8px', animation: 'fadeIn 0.2s ease' },
  errorBox: { background: 'var(--red-bg)', border: '1px solid rgba(255,77,77,0.25)', borderRadius: 8, padding: '12px 16px', marginBottom: 16 },
  errorText: { color: 'var(--red)', fontFamily: 'var(--mono)', fontSize: 12 },
  findingsHeader: { display: 'flex', alignItems: 'center', gap: 12, marginBottom: 16 },
  findingsTitle: { fontSize: 14, fontWeight: 600, color: 'var(--text)', fontFamily: 'var(--mono)', letterSpacing: '0.05em' },
  findingsCount: { fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--text-dim)' },
  empty: { color: 'var(--text-dim)', fontFamily: 'var(--mono)', fontSize: 13 },
  footer: { borderTop: '1px solid var(--border)', padding: '16px 24px', textAlign: 'center', fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--text-dim)', letterSpacing: '0.05em' },
  dastSummary: { background: 'var(--bg2)', border: '1px solid var(--border)', borderRadius: 10, padding: '18px 24px', marginBottom: 24 },
  dastMeta: { display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16, flexWrap: 'wrap' },
  dastTarget: { fontFamily: 'var(--mono)', fontSize: 14, color: 'var(--green)', fontWeight: 700 },
  sep: { color: 'var(--border2)' },
  dastDim: { fontFamily: 'var(--mono)', fontSize: 12, color: 'var(--text-dim)' },
  dastStats: { display: 'flex', gap: 32, flexWrap: 'wrap', marginBottom: 12 },
  paramsRow: { display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' },
  paramsLabel: { fontFamily: 'var(--mono)', fontSize: 9, color: 'var(--text-dim)', letterSpacing: '0.1em', fontWeight: 700 },
  paramTag: { fontFamily: 'var(--mono)', fontSize: 10, color: 'var(--text-dim)', background: 'var(--bg3)', border: '1px solid var(--border)', borderRadius: 4, padding: '2px 8px' },
}
