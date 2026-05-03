import { useState } from 'react'

export default function ScanForm({ onScan, scanning }) {
  const [target, setTarget] = useState('')
  const [portStart, setPortStart] = useState('1')
  const [portEnd, setPortEnd] = useState('1024')
  const [skipCve, setSkipCve] = useState(false)

  const handleSubmit = (e) => {
    e.preventDefault()
    if (!target.trim()) return
    onScan({
      target: target.trim(),
      port_start: parseInt(portStart),
      port_end: parseInt(portEnd),
      skip_cve: skipCve,
    })
  }

  const presets = [
    { label: 'Top 100', start: 1, end: 100 },
    { label: '1–1024', start: 1, end: 1024 },
    { label: 'Full', start: 1, end: 65535 },
  ]

  return (
    <form onSubmit={handleSubmit} style={styles.form}>
      <div style={styles.row}>
        <div style={styles.fieldWide}>
          <label style={styles.label}>TARGET</label>
          <input
            style={styles.input}
            value={target}
            onChange={e => setTarget(e.target.value)}
            placeholder="scanme.nmap.org or 192.168.1.1"
            disabled={scanning}
            spellCheck={false}
            autoComplete="off"
          />
        </div>

        <div style={styles.fieldNarrow}>
          <label style={styles.label}>PORT START</label>
          <input
            style={styles.input}
            value={portStart}
            onChange={e => setPortStart(e.target.value)}
            type="number"
            min="1"
            max="65535"
            disabled={scanning}
          />
        </div>

        <div style={styles.fieldNarrow}>
          <label style={styles.label}>PORT END</label>
          <input
            style={styles.input}
            value={portEnd}
            onChange={e => setPortEnd(e.target.value)}
            type="number"
            min="1"
            max="65535"
            disabled={scanning}
          />
        </div>
      </div>

      <div style={styles.row2}>
        <div style={styles.presets}>
          {presets.map(p => (
            <button
              key={p.label}
              type="button"
              style={styles.preset}
              onClick={() => { setPortStart(String(p.start)); setPortEnd(String(p.end)) }}
              disabled={scanning}
            >
              {p.label}
            </button>
          ))}
        </div>

        <label style={styles.checkbox}>
          <input
            type="checkbox"
            checked={skipCve}
            onChange={e => setSkipCve(e.target.checked)}
            disabled={scanning}
            style={{ accentColor: 'var(--green)', marginRight: 6 }}
          />
          <span style={{ color: 'var(--gray)', fontSize: 12 }}>Skip CVE lookup (faster)</span>
        </label>

        <button
          type="submit"
          disabled={scanning || !target.trim()}
          style={scanning ? styles.btnDisabled : styles.btn}
        >
          {scanning ? (
            <span style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={styles.spinner} /> SCANNING...
            </span>
          ) : '▶  RUN SCAN'}
        </button>
      </div>
    </form>
  )
}

const styles = {
  form: {
    background: 'var(--bg2)',
    border: '1px solid var(--border)',
    borderRadius: 12,
    padding: '24px',
    marginBottom: 24,
    display: 'flex',
    flexDirection: 'column',
    gap: 16,
  },
  row: {
    display: 'flex',
    gap: 12,
    flexWrap: 'wrap',
  },
  row2: {
    display: 'flex',
    alignItems: 'center',
    gap: 12,
    flexWrap: 'wrap',
  },
  fieldWide: { flex: '2 1 240px', display: 'flex', flexDirection: 'column', gap: 6 },
  fieldNarrow: { flex: '1 1 100px', display: 'flex', flexDirection: 'column', gap: 6 },
  label: {
    fontFamily: 'var(--mono)',
    fontSize: 10,
    letterSpacing: '0.12em',
    color: 'var(--green)',
    fontWeight: 700,
  },
  input: {
    background: 'var(--bg3)',
    border: '1px solid var(--border2)',
    borderRadius: 6,
    color: 'var(--text)',
    fontFamily: 'var(--mono)',
    fontSize: 13,
    padding: '9px 12px',
    outline: 'none',
    transition: 'border-color 0.15s',
  },
  presets: { display: 'flex', gap: 6 },
  preset: {
    background: 'transparent',
    border: '1px solid var(--border2)',
    borderRadius: 6,
    color: 'var(--gray)',
    fontSize: 11,
    fontFamily: 'var(--mono)',
    padding: '6px 12px',
    cursor: 'pointer',
    transition: 'all 0.15s',
  },
  checkbox: { display: 'flex', alignItems: 'center', cursor: 'pointer', marginLeft: 4 },
  btn: {
    marginLeft: 'auto',
    background: 'var(--green)',
    border: 'none',
    borderRadius: 6,
    color: '#000',
    fontFamily: 'var(--mono)',
    fontSize: 12,
    fontWeight: 700,
    padding: '10px 24px',
    cursor: 'pointer',
    letterSpacing: '0.08em',
  },
  btnDisabled: {
    marginLeft: 'auto',
    background: 'var(--bg3)',
    border: '1px solid var(--border2)',
    borderRadius: 6,
    color: 'var(--gray)',
    fontFamily: 'var(--mono)',
    fontSize: 12,
    fontWeight: 700,
    padding: '10px 24px',
    cursor: 'not-allowed',
    letterSpacing: '0.08em',
  },
  spinner: {
    display: 'inline-block',
    width: 10,
    height: 10,
    border: '2px solid var(--border2)',
    borderTopColor: 'var(--green)',
    borderRadius: '50%',
    animation: 'spin 0.7s linear infinite',
  },
}
