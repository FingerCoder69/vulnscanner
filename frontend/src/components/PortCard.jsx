import { useState } from 'react'

const SEV_COLORS = {
  CRITICAL: { color: '#ff4d4d', bg: 'rgba(255,77,77,0.1)', border: 'rgba(255,77,77,0.25)' },
  HIGH:     { color: '#ffb740', bg: 'rgba(255,183,64,0.1)', border: 'rgba(255,183,64,0.25)' },
  MEDIUM:   { color: '#4da6ff', bg: 'rgba(77,166,255,0.1)', border: 'rgba(77,166,255,0.25)' },
  LOW:      { color: '#00ff88', bg: 'rgba(0,255,136,0.1)', border: 'rgba(0,255,136,0.2)' },
  UNKNOWN:  { color: '#8892a4', bg: 'rgba(136,146,164,0.1)', border: 'rgba(136,146,164,0.2)' },
}

function Badge({ severity }) {
  const c = SEV_COLORS[severity] || SEV_COLORS.UNKNOWN
  return (
    <span style={{
      background: c.bg, border: `1px solid ${c.border}`, color: c.color,
      borderRadius: 20, padding: '2px 10px', fontSize: 10,
      fontFamily: 'var(--mono)', fontWeight: 700, letterSpacing: '0.06em',
    }}>
      {severity}
    </span>
  )
}

async function fetchAIAnalysis(entry) {
  const response = await fetch('http://localhost:8000/ai/analyse-port', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ entry }),
  })
  return await response.json()
}

export default function PortCard({ entry }) {
  if (!entry) return null
  const { port, service, banner, cves } = entry
  const topSev = cves?.[0]?.severity || null

  const [aiData, setAiData] = useState(null)
  const [aiLoading, setAiLoading] = useState(false)
  const [aiError, setAiError] = useState(null)
  const [expanded, setExpanded] = useState(false)

  const handleAnalyze = async () => {
    setAiLoading(true)
    setAiError(null)
    setExpanded(true)
    try {
      const result = await fetchAIAnalysis(entry)
      setAiData(result)
    } catch (e) {
      setAiError('AI analysis failed. Check your API key.')
    } finally {
      setAiLoading(false)
    }
  }

  return (
    <div style={styles.card}>
      {/* Header */}
      <div style={styles.header}>
        <div style={styles.portTag}>
          <span style={styles.portNum}>{port}</span>
          <span style={styles.portProto}>/TCP</span>
        </div>
        <span style={styles.service}>{service}</span>
        {topSev && <Badge severity={topSev} />}
        <span style={styles.cveCount}>{cves?.length || 0} CVE{cves?.length !== 1 ? 's' : ''}</span>

        {/* AI button */}
        {cves?.length > 0 && !aiData && (
          <button
            style={aiLoading ? styles.aiBtnLoading : styles.aiBtn}
            onClick={handleAnalyze}
            disabled={aiLoading}
          >
            {aiLoading
              ? <><span style={styles.spinner} /> Analysing...</>
              : <><span style={styles.aiIcon}>✦</span> AI Analyse</>
            }
          </button>
        )}
        {aiData && (
          <button
            style={styles.aiToggleBtn}
            onClick={() => setExpanded(e => !e)}
          >
            <span style={styles.aiIcon}>✦</span> AI {expanded ? '▲' : '▼'}
          </button>
        )}
      </div>

      {/* Banner */}
      <div style={styles.banner}>
        <span style={styles.bannerLabel}>BANNER</span>
        <span style={styles.bannerText}>{banner}</span>
      </div>

      {/* CVE list */}
      {cves && cves.length > 0 && (
        <div style={styles.cveList}>
          {cves.map(cve => (
            <div key={cve.id} style={styles.cveRow}>
              <div style={styles.cveLeft}>
                <a href={cve.url} target="_blank" rel="noreferrer" style={styles.cveId}>
                  {cve.id}
                </a>
                <Badge severity={cve.severity} />
                <span style={styles.score}>{cve.score}</span>
              </div>
              <p style={styles.cveDesc}>{cve.description.slice(0, 180)}...</p>
            </div>
          ))}
        </div>
      )}

      {/* AI Panel */}
      {aiError && (
        <div style={styles.aiError}>[!] {aiError}</div>
      )}

      {aiData && expanded && (
        <div style={styles.aiPanel}>
          <div style={styles.aiPanelHeader}>
            <span style={styles.aiTag}>✦ AI ANALYSIS</span>
            <span style={styles.aiModel}>claude-sonnet</span>
          </div>

          {aiData.risk_summary && (
            <div style={styles.aiBlock}>
              <div style={styles.aiBlockLabel}>RISK SUMMARY</div>
              <div style={styles.aiBlockText}>{aiData.risk_summary}</div>
            </div>
          )}

          {aiData.most_dangerous_cve && (
            <div style={styles.aiBlock}>
              <div style={styles.aiBlockLabel}>MOST DANGEROUS CVE</div>
              <div style={{ ...styles.aiBlockText, color: '#ff4d4d' }}>{aiData.most_dangerous_cve}</div>
            </div>
          )}

          {aiData.exploit_scenario && (
            <div style={styles.aiBlock}>
              <div style={styles.aiBlockLabel}>EXPLOIT SCENARIO</div>
              <div style={styles.aiBlockText}>{aiData.exploit_scenario}</div>
            </div>
          )}

          {aiData.fix && (
            <div style={styles.aiBlock}>
              <div style={styles.aiBlockLabel}>HOW TO FIX</div>
              <div style={{ ...styles.aiBlockText, ...styles.fixCode }}>{aiData.fix}</div>
            </div>
          )}

          {aiData.attack_commands?.length > 0 && (
            <div style={styles.aiBlock}>
              <div style={styles.aiBlockLabel}>ATTACKER WOULD RUN</div>
              <div style={styles.commandList}>
                {aiData.attack_commands.map((cmd, i) => (
                  <div key={i} style={styles.command}>
                    <span style={styles.prompt}>$</span>
                    <span style={styles.commandText}>{cmd}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

const styles = {
  card: {
    background: 'var(--bg2)', border: '1px solid var(--border)',
    borderRadius: 10, padding: '18px 20px', marginBottom: 12,
    transition: 'border-color 0.15s',
  },
  header: {
    display: 'flex', alignItems: 'center', gap: 12,
    marginBottom: 12, flexWrap: 'wrap',
  },
  portTag: {
    background: 'rgba(0,255,136,0.07)', border: '1px solid rgba(0,255,136,0.2)',
    borderRadius: 6, padding: '4px 12px', display: 'flex', alignItems: 'baseline', gap: 2,
  },
  portNum: { fontFamily: 'var(--mono)', fontSize: 15, color: 'var(--green)', fontWeight: 700 },
  portProto: { fontFamily: 'var(--mono)', fontSize: 10, color: 'var(--green-dim)' },
  service: { fontSize: 14, fontWeight: 600, color: 'var(--text)' },
  cveCount: { fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--text-dim)' },
  aiBtn: {
    marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 6,
    background: 'rgba(0,255,136,0.08)', border: '1px solid rgba(0,255,136,0.25)',
    borderRadius: 6, color: 'var(--green)', fontFamily: 'var(--mono)',
    fontSize: 11, fontWeight: 700, padding: '5px 12px', cursor: 'pointer',
    letterSpacing: '0.05em', transition: 'all 0.15s',
  },
  aiBtnLoading: {
    marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 6,
    background: 'transparent', border: '1px solid var(--border2)',
    borderRadius: 6, color: 'var(--text-dim)', fontFamily: 'var(--mono)',
    fontSize: 11, padding: '5px 12px', cursor: 'not-allowed', letterSpacing: '0.05em',
  },
  aiToggleBtn: {
    marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 6,
    background: 'rgba(0,255,136,0.12)', border: '1px solid rgba(0,255,136,0.3)',
    borderRadius: 6, color: 'var(--green)', fontFamily: 'var(--mono)',
    fontSize: 11, fontWeight: 700, padding: '5px 12px', cursor: 'pointer',
  },
  aiIcon: { fontSize: 12 },
  spinner: {
    display: 'inline-block', width: 9, height: 9,
    border: '2px solid var(--border2)', borderTopColor: 'var(--green)',
    borderRadius: '50%', animation: 'spin 0.7s linear infinite',
  },
  banner: {
    background: 'var(--bg3)', border: '1px solid var(--border)',
    borderRadius: 6, padding: '8px 12px', marginBottom: 12,
    display: 'flex', gap: 10, alignItems: 'flex-start',
  },
  bannerLabel: {
    fontFamily: 'var(--mono)', fontSize: 9, letterSpacing: '0.1em',
    color: 'var(--green)', fontWeight: 700, marginTop: 2, minWidth: 44,
  },
  bannerText: { fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--gray)', lineHeight: 1.6 },
  cveList: { display: 'flex', flexDirection: 'column', gap: 8, marginBottom: 12 },
  cveRow: {
    background: 'var(--bg3)', border: '1px solid var(--border)',
    borderRadius: 6, padding: '10px 14px',
  },
  cveLeft: { display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6, flexWrap: 'wrap' },
  cveId: { fontFamily: 'var(--mono)', fontSize: 12, color: 'var(--blue)', fontWeight: 700 },
  score: { fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--text-dim)' },
  cveDesc: { fontSize: 12, color: 'var(--gray)', lineHeight: 1.6 },
  aiError: {
    fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--red)',
    background: 'var(--red-bg)', border: '1px solid rgba(255,77,77,0.2)',
    borderRadius: 6, padding: '8px 12px', marginTop: 10,
  },
  aiPanel: {
    marginTop: 12, background: 'rgba(0,255,136,0.03)',
    border: '1px solid rgba(0,255,136,0.12)', borderRadius: 8,
    padding: '14px 16px', display: 'flex', flexDirection: 'column', gap: 14,
    animation: 'fadeIn 0.25s ease',
  },
  aiPanelHeader: { display: 'flex', alignItems: 'center', gap: 10 },
  aiTag: {
    fontFamily: 'var(--mono)', fontSize: 9, fontWeight: 700,
    letterSpacing: '0.1em', color: 'var(--green)',
    background: 'rgba(0,255,136,0.1)', border: '1px solid rgba(0,255,136,0.2)',
    borderRadius: 4, padding: '2px 8px',
  },
  aiModel: { fontFamily: 'var(--mono)', fontSize: 10, color: 'var(--text-dim)' },
  aiBlock: { display: 'flex', flexDirection: 'column', gap: 5 },
  aiBlockLabel: {
    fontFamily: 'var(--mono)', fontSize: 9,
    letterSpacing: '0.1em', color: 'var(--text-dim)', fontWeight: 700,
  },
  aiBlockText: { fontSize: 12, color: 'var(--text)', lineHeight: 1.7 },
  fixCode: {
    fontFamily: 'var(--mono)', fontSize: 11,
    background: 'var(--bg3)', borderRadius: 6,
    padding: '8px 12px', color: 'var(--green-dim)', whiteSpace: 'pre-wrap',
  },
  commandList: { display: 'flex', flexDirection: 'column', gap: 6 },
  command: {
    display: 'flex', alignItems: 'flex-start', gap: 10,
    background: '#080a0d', borderRadius: 6, padding: '8px 12px',
    fontFamily: 'var(--mono)', fontSize: 11,
  },
  prompt: { color: 'var(--green)', userSelect: 'none', marginTop: 1 },
  commandText: { color: '#e2e8f0', lineHeight: 1.6 },
}
