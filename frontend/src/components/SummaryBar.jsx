export default function SummaryBar({ data }) {
  if (!data) return null

  const { target, ip, port_range, timestamp, results } = data
  const totalCves = results.reduce((acc, r) => acc + (r.cves?.length || 0), 0)

  const sevCount = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }
  results.forEach(r => r.cves?.forEach(c => {
    if (c.severity in sevCount) sevCount[c.severity]++
  }))

  const time = new Date(timestamp).toLocaleTimeString()

  return (
    <div style={styles.wrap}>
      <div style={styles.meta}>
        <span style={styles.target}>{target}</span>
        <span style={styles.sep}>·</span>
        <span style={styles.dim}>{ip}</span>
        <span style={styles.sep}>·</span>
        <span style={styles.dim}>ports {port_range}</span>
        <span style={styles.sep}>·</span>
        <span style={styles.dim}>{time}</span>
      </div>

      <div style={styles.stats}>
        <Stat label="OPEN PORTS" value={results.length} color="var(--green)" />
        <Stat label="TOTAL CVES" value={totalCves} color="var(--text)" />
        <Stat label="CRITICAL" value={sevCount.CRITICAL} color="#ff4d4d" />
        <Stat label="HIGH" value={sevCount.HIGH} color="#ffb740" />
        <Stat label="MEDIUM" value={sevCount.MEDIUM} color="#4da6ff" />
        <Stat label="LOW" value={sevCount.LOW} color="var(--green)" />
      </div>
    </div>
  )
}

function Stat({ label, value, color }) {
  return (
    <div style={styles.stat}>
      <span style={{ ...styles.statVal, color }}>{value}</span>
      <span style={styles.statLabel}>{label}</span>
    </div>
  )
}

const styles = {
  wrap: {
    background: 'var(--bg2)',
    border: '1px solid var(--border)',
    borderRadius: 10,
    padding: '18px 24px',
    marginBottom: 24,
  },
  meta: {
    display: 'flex',
    alignItems: 'center',
    gap: 8,
    marginBottom: 16,
    flexWrap: 'wrap',
  },
  target: { fontFamily: 'var(--mono)', fontSize: 14, color: 'var(--green)', fontWeight: 700 },
  sep: { color: 'var(--border2)' },
  dim: { fontFamily: 'var(--mono)', fontSize: 12, color: 'var(--text-dim)' },
  stats: { display: 'flex', gap: 32, flexWrap: 'wrap' },
  stat: { display: 'flex', flexDirection: 'column', gap: 2 },
  statVal: { fontFamily: 'var(--mono)', fontSize: 28, fontWeight: 700, lineHeight: 1 },
  statLabel: { fontFamily: 'var(--mono)', fontSize: 9, letterSpacing: '0.12em', color: 'var(--text-dim)', fontWeight: 700 },
}
