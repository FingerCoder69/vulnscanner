import { useEffect, useRef } from 'react'

export default function Terminal({ lines, visible }) {
  const bottomRef = useRef(null)

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [lines])

  if (!visible) return null

  return (
    <div style={styles.wrap}>
      <div style={styles.header}>
        <div style={styles.dots}>
          <span style={{ ...styles.dot, background: '#ff5f57' }} />
          <span style={{ ...styles.dot, background: '#febc2e' }} />
          <span style={{ ...styles.dot, background: '#28c840' }} />
        </div>
        <span style={styles.title}>vulnscanner — terminal</span>
      </div>
      <div style={styles.body}>
        {lines.map((line, i) => (
          <div key={i} style={styles.line}>
            <span style={styles.prompt}>$</span>
            <span style={getLineStyle(line)}>{line}</span>
          </div>
        ))}
        <div style={styles.cursor}>█</div>
        <div ref={bottomRef} />
      </div>
    </div>
  )
}

function getLineStyle(line) {
  if (line.startsWith('[+]')) return { color: '#00ff88' }
  if (line.startsWith('[!]')) return { color: '#ff4d4d' }
  if (line.startsWith('[*]')) return { color: '#4da6ff' }
  if (line.startsWith('  [')) return { color: '#ffb740' }
  return { color: '#8892a4' }
}

const styles = {
  wrap: {
    background: '#080a0d',
    border: '1px solid var(--border)',
    borderRadius: 12,
    marginBottom: 24,
    overflow: 'hidden',
    fontFamily: 'var(--mono)',
  },
  header: {
    background: '#0f1117',
    borderBottom: '1px solid var(--border)',
    padding: '10px 16px',
    display: 'flex',
    alignItems: 'center',
    gap: 10,
  },
  dots: { display: 'flex', gap: 6 },
  dot: { width: 12, height: 12, borderRadius: '50%', display: 'inline-block' },
  title: { fontSize: 11, color: 'var(--text-dim)', letterSpacing: '0.05em' },
  body: {
    padding: '16px 20px',
    maxHeight: 320,
    overflowY: 'auto',
    fontSize: 12,
    lineHeight: 1.8,
  },
  line: { display: 'flex', gap: 10 },
  prompt: { color: 'var(--green)', userSelect: 'none', minWidth: 10 },
  cursor: {
    color: 'var(--green)',
    animation: 'blink 1s step-end infinite',
    fontSize: 12,
    marginTop: 4,
  },
}
