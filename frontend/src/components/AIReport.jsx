const RISK_COLORS = {
  Critical: '#ff4d4d',
  High: '#ffb740',
  Medium: '#4da6ff',
  Low: '#00ff88',
  Informational: '#8892a4',
}

export default function AIReport({ report }) {
  if (!report) return null

  const riskColor = RISK_COLORS[report.risk_rating] || '#8892a4'

  return (
    <div style={styles.wrap}>
      <div style={styles.header}>
        <span style={styles.aiTag}>AI PENTEST REPORT</span>
        <span style={{ ...styles.riskBadge, color: riskColor, borderColor: riskColor + '40', background: riskColor + '12' }}>
          {report.risk_rating}
        </span>
      </div>

      {report.executive_summary && (
        <div style={styles.section}>
          <div style={styles.sectionLabel}>EXECUTIVE SUMMARY</div>
          <div style={styles.sectionText}>{report.executive_summary}</div>
        </div>
      )}

      {report.attack_surface && (
        <div style={styles.section}>
          <div style={styles.sectionLabel}>ATTACK SURFACE</div>
          <div style={styles.sectionText}>{report.attack_surface}</div>
        </div>
      )}

      {report.immediate_actions && report.immediate_actions.length > 0 && (
        <div style={styles.section}>
          <div style={styles.sectionLabel}>IMMEDIATE ACTIONS</div>
          <ol style={styles.list}>
            {report.immediate_actions.map((a, i) => (
              <li key={i} style={styles.listItem}>{a}</li>
            ))}
          </ol>
        </div>
      )}

      {report.key_findings && report.key_findings.length > 0 && (
        <div style={styles.section}>
          <div style={styles.sectionLabel}>KEY FINDINGS</div>
          <div style={styles.findingsList}>
            {report.key_findings.map((f, i) => (
              <div key={i} style={styles.findingRow}>
                <div style={styles.findingTitle}>{f.title}</div>
                <div style={styles.findingImpact}>{f.impact}</div>
                <div style={styles.findingRec}>{f.recommendation}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {report.conclusion && (
        <div style={styles.section}>
          <div style={styles.sectionLabel}>CONCLUSION</div>
          <div style={{ ...styles.sectionText, color: 'var(--text-dim)', fontStyle: 'italic' }}>{report.conclusion}</div>
        </div>
      )}
    </div>
  )
}

const styles = {
  wrap: {
    background: 'var(--bg2)',
    border: '1px solid rgba(0,255,136,0.15)',
    borderRadius: 12, padding: '24px',
    marginBottom: 24,
  },
  header: { display: 'flex', alignItems: 'center', gap: 12, marginBottom: 20 },
  aiTag: {
    fontFamily: 'var(--mono)', fontSize: 10, fontWeight: 700,
    letterSpacing: '0.1em', color: 'var(--green)',
    background: 'rgba(0,255,136,0.1)', border: '1px solid rgba(0,255,136,0.2)',
    borderRadius: 4, padding: '4px 10px',
  },
  riskBadge: {
    fontFamily: 'var(--mono)', fontSize: 11, fontWeight: 700,
    border: '1px solid', borderRadius: 20,
    padding: '3px 12px', letterSpacing: '0.06em',
  },
  section: { marginBottom: 18 },
  sectionLabel: {
    fontFamily: 'var(--mono)', fontSize: 9, fontWeight: 700,
    letterSpacing: '0.12em', color: 'var(--text-dim)',
    marginBottom: 8,
  },
  sectionText: { fontSize: 13, color: 'var(--text)', lineHeight: 1.7 },
  list: { paddingLeft: 20, display: 'flex', flexDirection: 'column', gap: 6 },
  listItem: { fontSize: 12, color: 'var(--text)', lineHeight: 1.6 },
  findingsList: { display: 'flex', flexDirection: 'column', gap: 10 },
  findingRow: {
    background: 'var(--bg3)', borderRadius: 8,
    padding: '12px 14px',
  },
  findingTitle: { fontFamily: 'var(--mono)', fontSize: 12, color: 'var(--green)', fontWeight: 700, marginBottom: 4 },
  findingImpact: { fontSize: 12, color: 'var(--text)', marginBottom: 4 },
  findingRec: { fontSize: 11, color: 'var(--text-dim)', fontStyle: 'italic' },
}
