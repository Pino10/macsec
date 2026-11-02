/** Formats answers and reports from AI: headings, numbered steps, `code`, **bold** and *italics*. */
/** Tiny formatter for model answers: paragraphs, numbered steps and `code`. */
export function Answer({ text }: { text: string }): React.JSX.Element {
  const inline = (line: string): React.ReactNode[] =>
    line.split(/(`[^`]+`|\*\*[^*]+\*\*|\*[^*\s][^*]*\*)/g).map((part, i) =>
      part.length > 2 && part.startsWith('`') && part.endsWith('`') ? (
        <code key={i}>{part.slice(1, -1)}</code>
      ) : part.length > 4 && part.startsWith('**') && part.endsWith('**') ? (
        <strong key={i}>{inline(part.slice(2, -2))}</strong>
      ) : part.length > 2 && part.startsWith('*') && part.endsWith('*') ? (
        <em key={i}>{inline(part.slice(1, -1))}</em>
      ) : (
        part
      )
    )
  const blocks: React.ReactNode[] = []
  const lines = text.replace(/<think>[\s\S]*?<\/think>/g, '').trim().split('\n')
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]
    if (line.startsWith('```')) {
      const body: string[] = []
      for (i++; i < lines.length && !lines[i].startsWith('```'); i++) body.push(lines[i])
      blocks.push(
        <pre key={i} className="code-block">
          {body.join('\n')}
        </pre>
      )
    } else if (line.trim()) {
      const m = /^\s*(\d+[.)]|[-*])\s+(.*)$/.exec(line)
      blocks.push(
        m ? (
          <div key={i} className="ans-step">
            <span>{/\d/.test(m[1]) ? m[1].replace(')', '.') : '•'}</span>
            <p>{inline(m[2])}</p>
          </div>
        ) : (
          /^#{1,4}\s/.test(line) ? (
            <h4 key={i} className="ans-h" data-sev={/\[(CRITICAL|HIGH|MEDIUM|LOW)\]/i.exec(line)?.[1].toLowerCase()}>
              {inline(line.replace(/^#+\s*/, '').replace(/\[(CRITICAL|HIGH|MEDIUM|LOW)\]\s*/i, ''))}
              {/\[(CRITICAL|HIGH|MEDIUM|LOW)\]/i.test(line) && <span className="sev" data-sev={/\[(CRITICAL|HIGH|MEDIUM|LOW)\]/i.exec(line)![1].toLowerCase()}>{/\[(CRITICAL|HIGH|MEDIUM|LOW)\]/i.exec(line)![1].toLowerCase()}</span>}
            </h4>
          ) : (
            <p key={i}>{inline(line)}</p>
          )
        )
      )
    }
  }
  return <div className="answer">{blocks}</div>
}

