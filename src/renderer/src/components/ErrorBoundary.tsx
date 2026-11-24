import { Component, type ErrorInfo, type ReactNode } from 'react'
import { AlertTriangle, FolderOpen, RotateCw } from 'lucide-react'

interface State {
  error: Error | null
}

/**
 * A window that fails to render shows this instead of an empty screen. MacSec reads untrusted data
 * (scanner output, source maps, model answers), so a single bad value must not take the app with it.
 */
export default class ErrorBoundary extends Component<{ children: ReactNode }, State> {
  state: State = { error: null }

  static getDerivedStateFromError(error: Error): State {
    return { error }
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    // Keep it in the window's console (View, Toggle Developer Tools) without a second failure.
    console.error('MacSec window error:', error, info.componentStack)
  }

  render(): ReactNode {
    if (!this.state.error) return this.props.children
    return (
      <div className="page" style={{ padding: 24 }}>
        <div className="empty-state" style={{ display: 'grid', gap: 12, justifyItems: 'start', maxWidth: 720 }}>
          <strong style={{ display: 'flex', gap: 8, alignItems: 'center', fontSize: 17 }}>
            <AlertTriangle size={18} style={{ color: 'var(--bad)' }} /> This page could not be drawn
          </strong>
          <span>
            The rest of MacSec is still running, and no test was stopped by this. Your sessions and settings are on disk and are not affected.
          </span>
          <pre className="codeview" style={{ maxHeight: 220, overflow: 'auto', padding: 12, width: '100%' }}>
            {String(this.state.error?.stack ?? this.state.error?.message ?? 'Unknown error').slice(0, 2000)}
          </pre>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            <button className="btn btn-primary" onClick={() => window.location.reload()}>
              <RotateCw size={14} /> Reload the window
            </button>
            <button className="btn" onClick={() => void window.macsec.invoke('app:open-folder', 'root')}>
              <FolderOpen size={14} /> Open the MacSec folder
            </button>
            <button
              className="btn"
              onClick={() => void navigator.clipboard.writeText(String(this.state.error?.stack ?? this.state.error?.message ?? ''))}
            >
              Copy the error
            </button>
            <button className="btn" onClick={() => this.setState({ error: null })}>
              Try again
            </button>
          </div>
          <span className="hint">Paste that text into an issue on GitHub, with what you were doing just before.</span>
        </div>
      </div>
    )
  }
}
