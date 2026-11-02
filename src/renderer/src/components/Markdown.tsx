import { Fragment } from 'react'

/** Bold, inline code and italics, as React elements (never HTML). */
function inline(text: string): React.ReactNode[] {
  const out: React.ReactNode[] = []
  const re = /(\*\*[^*]+\*\*|`[^`]+`)/g
  let last = 0
  for (const m of text.matchAll(re)) {
    if (m.index! > last) out.push(text.slice(last, m.index))
    const t = m[0]
    out.push(t.startsWith('**') ? <strong key={m.index}>{t.slice(2, -2)}</strong> : <code key={m.index}>{t.slice(1, -1)}</code>)
    last = m.index! + t.length
  }
  if (last < text.length) out.push(text.slice(last))
  return out
}

const SEV = /^\[(CRITICAL|HIGH|MEDIUM|LOW)\]\s*/i

/** Renders the AI's report: headings (with severity pills), lists, tables and code blocks. */
export default function Markdown({ text }: { text: string }): React.JSX.Element {
  const lines = text.replace(/<think>[\s\S]*?<\/think>/g, '').split('\n')
  const blocks: React.ReactNode[] = []
  let i = 0
  while (i < lines.length) {
    const line = lines[i]
    if (/^```/.test(line)) {
      const code: string[] = []
      i++
      while (i < lines.length && !/^```/.test(lines[i])) code.push(lines[i++])
      i++
      blocks.push(<pre key={blocks.length}>{code.join('\n')}</pre>)
      continue
    }
    if (/^\s*\|.*\|\s*$/.test(line)) {
      const rows: string[][] = []
      while (i < lines.length && /^\s*\|.*\|\s*$/.test(lines[i])) {
        if (!/^\s*\|[\s:|-]+\|\s*$/.test(lines[i])) rows.push(lines[i].trim().slice(1, -1).split('|').map((c) => c.trim()))
        i++
      }
      const [head, ...body] = rows
      blocks.push(
        <table key={blocks.length}>
          <thead>
            <tr>{head?.map((c, j) => <th key={j}>{inline(c)}</th>)}</tr>
          </thead>
          <tbody>
            {body.map((r, k) => (
              <tr key={k}>
                {r.map((c, j) => {
                  const sev = /^(critical|high|medium|low|info)$/i.exec(c.replace(/\*/g, ''))
                  return (
                    <td key={j}>
                      {sev ? (
                        <span className="sev" data-sev={sev[1].toLowerCase()}>
                          {sev[1].toLowerCase()}
                        </span>
                      ) : (
                        inline(c)
                      )}
                    </td>
                  )
                })}
              </tr>
            ))}
          </tbody>
        </table>
      )
      continue
    }
    const h = /^(#{1,4})\s+(.*)$/.exec(line)
    if (h) {
      const level = h[1].length
      const sev = SEV.exec(h[2])
      const content = (
        <>
          {sev && (
            <span className="sev" data-sev={sev[1].toLowerCase()}>
              {sev[1].toLowerCase()}
            </span>
          )}
          {inline(h[2].replace(SEV, ''))}
        </>
      )
      blocks.push(level <= 2 ? <h2 key={blocks.length}>{content}</h2> : level === 3 ? <h3 key={blocks.length}>{content}</h3> : <h4 key={blocks.length}>{content}</h4>)
      i++
      continue
    }
    if (/^\s*([-*]|\d+\.)\s+/.test(line)) {
      const ordered = /^\s*\d+\./.test(line)
      const items: string[] = []
      while (i < lines.length && /^\s*([-*]|\d+\.)\s+/.test(lines[i])) items.push(lines[i++].replace(/^\s*([-*]|\d+\.)\s+/, ''))
      const L = ordered ? 'ol' : 'ul'
      blocks.push(
        <L key={blocks.length}>
          {items.map((t, k) => (
            <li key={k}>{inline(t)}</li>
          ))}
        </L>
      )
      continue
    }
    if (line.trim()) blocks.push(<p key={blocks.length}>{inline(line)}</p>)
    i++
  }
  return <Fragment>{blocks}</Fragment>
}
