import { useState } from 'react'

export default function DASTForm({ onScan, scanning }) {
  const [target, setTarget] = useState('')
  const [aiTriage, setAiTriage] = useState(true)
  const [genReport, setGenReport] = useState(false)

  const handleSubmit = (e) => {
    e.preventDefault()
    if (!target.trim()) return
    onScan({
      target: target.trim(),
      ai_triage: aiTriage,
      generate_report: genReport,
    })
  }

  const examples = ['https://juice-shop.herokuapp.com', 'https://testphp.vulnweb.com', 'https://httpbin.org']

  return (
    <form onSubmit={handleSubmit} style={styles.form}>
      {/* Info banner */}
      <div style={styles.infoBanner}>
        <span style={styles.infoIcon}>⚡</span>
        <span style={styles.infoText}>
          DAST actively probes the target with attack payloads. Only scan targets you own or have written permission to test.
        </span>
      </div>

      <div style={styles.row}>
        <div style={styles.fieldWide}>
          <label style={styles.label}>TARGET URL</label>
          <input
            style={styles.input}
            value={target}
            onChange={e => setTarget(e.target.value)}
            placeholder="https://target-app.com"
            disabled={scanning}
            spellCheck={false}
            autoComplete="off"
          />
        </div>
      </div>

      {/* Quick examples */}
      <div style={styles.examplesRow}>
        <span style={styles.examplesLabel}>TRY:</span>
        {examples.map(ex => (
          <button
            key={ex}
            type="button"
            style={styles.exampleBtn}
            onClick={() => setTarget(ex)}
            disabled={scanning}
          >
            {ex.replace('https://', '')}
          </button>
        ))}
      </div>

      <div style={styles.row2}>
        <div style={styles.toggles}>
          <label style={styles.toggle}>
            <input
              type="checkbox"
              checked={aiTriage}
              onChange={e => setAiTriage(e.target.checked)}
              disabled={scanning}
              style={{ accentColor: 'var(--green)', marginRight: 6 }}
            />
            <span style={styles.toggleLabel}>
              <span style={styles.aiTag}>AI</span>
              Triage findings
            </span>
          </label>

          <label style={styles.toggle}>
            <input
              type="checkbox"
              checked={genReport}
              onChange={e => setGenReport(e.target.checked)}
              disabled={scanning}
              style={{ accentColor: 'var(--green)', marginRight: 6 }}
            />
            <span style={styles.toggleLabel}>
              <span style={styles.aiTag}>AI</span>
              Generate pentest report
            </span>
          </label>
        </div>

        <button
          type="submit"
          disabled={scanning || !target.trim()}
          style={scanning ? styles.btnDisabled : styles.btn}
        >
          {scanning ? (
            <span style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={styles.spinner} /> SCANNING...
            </span>
          ) : '▶  RUN DAST'}
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
  infoBanner: {
    background: 'rgba(255,183,64,0.07)',
    border: '1px solid rgba(255,183,64,0.2)',
    borderRadius: 8,
    padding: '10px 14px',
    display: 'flex',
    alignItems: 'flex-start',
    gap: 10,
  },
  infoIcon: { fontSize: 14, marginTop: 1 },
  infoText: { fontSize: 11, color: '#ffb740', fontFamily: 'var(--mono)', lineHeight: 1.6 },
  row: { display: 'flex', gap: 12, flexWrap: 'wrap' },
  row2: { display: 'flex', alignItems: 'center', gap: 16, flexWrap: 'wrap' },
  fieldWide: { flex: '1 1 300px', display: 'flex', flexDirection: 'column', gap: 6 },
  label: {
    fontFamily: 'var(--mono)', fontSize: 10,
    letterSpacing: '0.12em', color: 'var(--green)', fontWeight: 700,
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
  examplesRow: {
    display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap',
  },
  examplesLabel: {
    fontFamily: 'var(--mono)', fontSize: 9,
    color: 'var(--text-dim)', letterSpacing: '0.12em', fontWeight: 700,
  },
  exampleBtn: {
    background: 'transparent',
    border: '1px solid var(--border2)',
    borderRadius: 6,
    color: 'var(--gray)',
    fontSize: 10,
    fontFamily: 'var(--mono)',
    padding: '4px 10px',
    cursor: 'pointer',
  },
  toggles: { display: 'flex', gap: 20, flexWrap: 'wrap' },
  toggle: { display: 'flex', alignItems: 'center', cursor: 'pointer' },
  toggleLabel: { display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, color: 'var(--gray)' },
  aiTag: {
    background: 'rgba(0,255,136,0.12)',
    border: '1px solid rgba(0,255,136,0.25)',
    color: 'var(--green)',
    fontFamily: 'var(--mono)',
    fontSize: 9,
    fontWeight: 700,
    padding: '1px 5px',
    borderRadius: 3,
    letterSpacing: '0.05em',
  },
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
    display: 'inline-block', width: 10, height: 10,
    border: '2px solid var(--border2)',
    borderTopColor: 'var(--green)',
    borderRadius: '50%',
    animation: 'spin 0.7s linear infinite',
  },
}
