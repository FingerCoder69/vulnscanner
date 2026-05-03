import { useState } from 'react'

const SEV_COLORS = {
  CRITICAL: { color: '#ff4d4d', bg: 'rgba(255,77,77,0.1)', border: 'rgba(255,77,77,0.25)' },
  HIGH:     { color: '#ffb740', bg: 'rgba(255,183,64,0.1)', border: 'rgba(255,183,64,0.25)' },
  MEDIUM:   { color: '#4da6ff', bg: 'rgba(77,166,255,0.1)', border: 'rgba(77,166,255,0.25)' },
  LOW:      { color: '#00ff88', bg: 'rgba(0,255,136,0.1)', border: 'rgba(0,255,136,0.2)'  },
  UNKNOWN:  { color: '#8892a4', bg: 'rgba(136,146,164,0.1)', border: 'rgba(136,146,164,0.2)' },
}

const CATEGORY_ICONS = {
  'Injection': '💉',
  'XSS': '🎭',
  'Security Misconfiguration': '⚙️',
  'Broken Access Control': '🔓',
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

export default function DASTFindingCard({ finding, index }) {
  const [expanded, setExpanded] = useState(false)
  const { check, severity, score, detail, evidence, url, category, ai, payload, param } = finding
  const c = SEV_COLORS[severity] || SEV_COLORS.UNKNOWN
  const icon = CATEGORY_ICONS[category] || '🔍'

  return (
    <div style={{ ...styles.card, borderLeft: `3px solid ${c.color}` }}>
      {/* Header */}
      <div style={styles.header} onClick={() => setExpanded(e => !e)}>
        <div style={styles.headerLeft}>
          <span style={styles.icon}>{icon}</span>
          <div>
            <div style={styles.checkName}>{check}</div>
            <div style={styles.category}>{category}</div>
          </div>
        </div>
        <div style={styles.headerRight}>
          <Badge severity={severity} />
          <span style={{ ...styles.score, color: c.color }}>{score}</span>
          <span style={styles.chevron}>{expanded ? '▲' : '▼'}</span>
        </div>
      </div>

      {/* Always visible: detail + evidence */}
      <div style={styles.detailRow}>
        <span style={styles.detailLabel}>DETAIL</span>
        <span style={styles.detailText}>{detail}</span>
      </div>
      {evidence && (
        <div style={styles.evidenceRow}>
          <span style={styles.detailLabel}>EVIDENCE</span>
          <span style={styles.evidenceText}>{evidence}</span>
        </div>
      )}
      {url && url !== finding.url && (
        <div style={styles.urlRow}>
          <span style={styles.detailLabel}>URL</span>
          <a href={url} target="_blank" rel="noreferrer" style={styles.urlText}>{url}</a>
        </div>
      )}

      {/* Expanded: AI triage */}
      {expanded && ai && (
        <div style={styles.aiSection}>
          <div style={styles.aiHeader}>
            <span style={styles.aiTag}>AI TRIAGE</span>
            <span style={styles.aiModel}>claude-sonnet</span>
          </div>

          <div style={styles.aiBlock}>
            <div style={styles.aiBlockLabel}>WHY IT'S DANGEROUS</div>
            <div style={styles.aiBlockText}>{ai.summary}</div>
          </div>

          {ai.exploit_scenario && (
            <div style={styles.aiBlock}>
              <div style={styles.aiBlockLabel}>EXPLOIT SCENARIO</div>
              <div style={styles.aiBlockText}>{ai.exploit_scenario}</div>
            </div>
          )}

          {ai.fix && (
            <div style={styles.aiBlock}>
              <div style={styles.aiBlockLabel}>HOW TO FIX</div>
              <div style={{ ...styles.aiBlockText, ...styles.fixCode }}>{ai.fix}</div>
            </div>
          )}

          {ai.attack_payloads && ai.attack_payloads.length > 0 && (
            <div style={styles.aiBlock}>
              <div style={styles.aiBlockLabel}>NEXT PAYLOADS TO TRY</div>
              <div style={styles.payloadList}>
                {ai.attack_payloads.map((p, i) => (
                  <span key={i} style={styles.payload}>{p}</span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Expanded: raw finding details */}
      {expanded && (param || payload) && (
        <div style={styles.rawSection}>
          {param && <div style={styles.rawRow}><span style={styles.rawKey}>PARAM</span><span style={styles.rawVal}>{param}</span></div>}
          {payload && <div style={styles.rawRow}><span style={styles.rawKey}>PAYLOAD</span><span style={styles.rawVal}>{payload}</span></div>}
        </div>
      )}

      {expanded && !ai && (
        <div style={styles.noAi}>AI triage not available for this finding</div>
      )}
    </div>
  )
}

const styles = {
  card: {
    background: 'var(--bg2)',
    border: '1px solid var(--border)',
    borderRadius: 10,
    padding: '16px 18px',
    marginBottom: 12,
    transition: 'border-color 0.15s',
  },
  header: {
    display: 'flex', alignItems: 'center',
    justifyContent: 'space-between', cursor: 'pointer',
    marginBottom: 12, flexWrap: 'wrap', gap: 8,
  },
  headerLeft: { display: 'flex', alignItems: 'center', gap: 12 },
  icon: { fontSize: 20 },
  checkName: { fontSize: 14, fontWeight: 600, color: 'var(--text)', fontFamily: 'var(--mono)' },
  category: { fontSize: 11, color: 'var(--text-dim)', marginTop: 2 },
  headerRight: { display: 'flex', alignItems: 'center', gap: 10 },
  score: { fontFamily: 'var(--mono)', fontSize: 20, fontWeight: 700, lineHeight: 1 },
  chevron: { fontFamily: 'var(--mono)', fontSize: 10, color: 'var(--text-dim)', marginLeft: 4 },
  detailRow: {
    background: 'var(--bg3)', borderRadius: 6, padding: '8px 12px',
    display: 'flex', gap: 10, marginBottom: 6,
  },
  evidenceRow: {
    background: 'rgba(255,183,64,0.04)', border: '1px solid rgba(255,183,64,0.1)',
    borderRadius: 6, padding: '8px 12px', display: 'flex', gap: 10, marginBottom: 6,
  },
  urlRow: {
    display: 'flex', gap: 10, alignItems: 'center', marginBottom: 6,
    padding: '4px 8px',
  },
  detailLabel: {
    fontFamily: 'var(--mono)', fontSize: 9, letterSpacing: '0.1em',
    color: 'var(--green)', fontWeight: 700, marginTop: 2, minWidth: 60,
  },
  detailText: { fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--gray)', lineHeight: 1.6 },
  evidenceText: { fontFamily: 'var(--mono)', fontSize: 11, color: '#ffb740', lineHeight: 1.6 },
  urlText: { fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--blue)' },
  aiSection: {
    marginTop: 12,
    background: 'rgba(0,255,136,0.03)',
    border: '1px solid rgba(0,255,136,0.1)',
    borderRadius: 8, padding: '14px 16px',
    display: 'flex', flexDirection: 'column', gap: 12,
  },
  aiHeader: { display: 'flex', alignItems: 'center', gap: 10 },
  aiTag: {
    fontFamily: 'var(--mono)', fontSize: 9, fontWeight: 700,
    letterSpacing: '0.1em', color: 'var(--green)',
    background: 'rgba(0,255,136,0.1)', border: '1px solid rgba(0,255,136,0.2)',
    borderRadius: 4, padding: '2px 8px',
  },
  aiModel: { fontFamily: 'var(--mono)', fontSize: 10, color: 'var(--text-dim)' },
  aiBlock: { display: 'flex', flexDirection: 'column', gap: 4 },
  aiBlockLabel: {
    fontFamily: 'var(--mono)', fontSize: 9, letterSpacing: '0.1em',
    color: 'var(--text-dim)', fontWeight: 700,
  },
  aiBlockText: { fontSize: 12, color: 'var(--text)', lineHeight: 1.7 },
  fixCode: {
    fontFamily: 'var(--mono)', fontSize: 11,
    background: 'var(--bg3)', borderRadius: 6,
    padding: '8px 12px', color: 'var(--green-dim)',
    whiteSpace: 'pre-wrap',
  },
  payloadList: { display: 'flex', flexWrap: 'wrap', gap: 6 },
  payload: {
    fontFamily: 'var(--mono)', fontSize: 10,
    background: 'rgba(255,77,77,0.08)', border: '1px solid rgba(255,77,77,0.2)',
    color: '#ff4d4d', borderRadius: 4, padding: '2px 8px',
  },
  rawSection: {
    marginTop: 10, display: 'flex', gap: 16, flexWrap: 'wrap',
    padding: '8px 12px', background: 'var(--bg3)', borderRadius: 6,
  },
  rawRow: { display: 'flex', gap: 8, alignItems: 'center' },
  rawKey: { fontFamily: 'var(--mono)', fontSize: 9, color: 'var(--text-dim)', letterSpacing: '0.1em', fontWeight: 700 },
  rawVal: { fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--amber)' },
  noAi: { marginTop: 10, fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--text-dim)' },
}
