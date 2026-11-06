import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react'
import type { AppInfo, AppSettings, JobInfo, SessionInfo, ToolInfo, UpdateInfo } from '@shared/types'

export interface Toast {
  kind: 'error' | 'info' | 'success'
  text: string
  /** A short heading. Without one, the text is the whole message. */
  title?: string
}

/** A message kept in the notification history. */
export interface Notice extends Toast {
  id: number
  at: string
  read: boolean
  /** Still shown as a pop-up. */
  popup: boolean
}

export type Page = 'overview' | 'projects' | 'review' | 'web' | 'api' | 'mobile' | 'recon' | 'audit' | 'mac' | 'sessions' | 'tools' | 'logs' | 'settings' | 'updates'

interface AppCtx {
  page: Page
  setPage: (p: Page) => void
  /** The session open on the Sessions page. */
  openSession: string | null
  showSession: (id: string | null) => void
  /** A project chosen on Projects, waiting on the Code review page. */
  preset: PresetSource | null
  setPreset: (p: PresetSource | null) => void
  appInfo: AppInfo | null
  settings: AppSettings | null
  updateSettings: (patch: Partial<AppSettings>) => Promise<void>
  setSettings: (s: AppSettings) => void
  sessions: SessionInfo[]
  setSessions: (s: SessionInfo[]) => void
  tools: ToolInfo[]
  setTools: (t: ToolInfo[]) => void
  jobs: JobInfo[]
  /** Tool names with a newer version, found by the daily check. */
  updates: string[]
  /** A newer MacSec, when there is one. */
  appUpdate: UpdateInfo | null
  /** Newest first. */
  notices: Notice[]
  /** Hide a pop-up but keep it in the history. */
  dismiss: (id: number) => void
  markRead: (id?: number) => void
  clearNotices: () => void
  busy: Set<string>
  act: <T>(key: string, fn: () => Promise<T>) => Promise<T | undefined>
  notify: (t: Toast) => void
}

export type PresetSource = { kind: 'local'; path: string; name: string } | { kind: 'github'; repo: string } | { kind: 'azure'; url: string; name: string }

const Ctx = createContext<AppCtx | null>(null)
export const api = (): Window['macsec'] => window.macsec

/** Electron prefixes errors from the main process; people only need the message. */
export const cleanError = (e: unknown): string =>
  String(e instanceof Error ? e.message : e)
    .replace(/^Error invoking remote method '[^']+': /, '')
    .replace(/^Error: /, '')

export function AppProvider({ children }: { children: React.ReactNode }): React.JSX.Element {
  const [page, setPageState] = useState<Page>('overview')
  const [openSession, setOpenSession] = useState<string | null>(null)
  const [preset, setPreset] = useState<PresetSource | null>(null)
  const [appInfo, setAppInfo] = useState<AppInfo | null>(null)
  const [settings, setSettings] = useState<AppSettings | null>(null)
  const [sessions, setSessions] = useState<SessionInfo[]>([])
  const [tools, setTools] = useState<ToolInfo[]>([])
  const [jobs, setJobs] = useState<JobInfo[]>([])
  const [updates, setUpdates] = useState<string[]>([])
  const [appUpdate, setAppUpdate] = useState<UpdateInfo | null>(null)
  const [notices, setNotices] = useState<Notice[]>([])
  const [busy, setBusy] = useState<Set<string>>(new Set())
  const noticeId = useRef(0)

  const notify = useCallback((t: Toast) => {
    const id = ++noticeId.current
    setNotices((list) => [{ ...t, id, at: new Date().toISOString(), read: false, popup: true }, ...list].slice(0, 60))
  }, [])
  const dismiss = useCallback((id: number) => setNotices((l) => l.map((n) => (n.id === id ? { ...n, popup: false, read: true } : n))), [])
  const markRead = useCallback((id?: number) => setNotices((l) => l.map((n) => (id === undefined || n.id === id ? { ...n, read: true, popup: false } : n))), [])
  const clearNotices = useCallback(() => setNotices([]), [])

  const act = useCallback(
    async <T,>(key: string, fn: () => Promise<T>): Promise<T | undefined> => {
      setBusy((b) => new Set(b).add(key))
      try {
        return await fn()
      } catch (e) {
        notify({ kind: 'error', text: cleanError(e) })
        return undefined
      } finally {
        setBusy((b) => {
          const n = new Set(b)
          n.delete(key)
          return n
        })
      }
    },
    [notify]
  )

  const setPage = useCallback((p: Page) => {
    setPageState(p)
    if (p !== 'sessions') setOpenSession(null)
  }, [])
  const showSession = useCallback((id: string | null) => {
    setOpenSession(id)
    if (id) setPageState('sessions')
  }, [])

  const updateSettings = useCallback(async (patch: Partial<AppSettings>) => {
    setSettings(await api().invoke('settings:set', patch))
  }, [])

  useEffect(() => {
    void api().invoke('app:info').then(setAppInfo)
    void api().invoke('settings:get').then(setSettings)
    void api().invoke('sessions:list').then(setSessions)
    void api().invoke('app:update-status').then((st) => setAppUpdate(st.update)).catch(() => undefined)
    void api()
      .invoke('tools:list')
      .then((t) => {
        setTools(t)
        setUpdates(t.filter((x) => x.updateAvailable).map((x) => x.name))
      })
    const offs = [
      api().on('jobs:changed', setJobs),
      api().on('notice', (n) => notify({ kind: n.kind, title: n.title, text: n.body ?? '' })),
      api().on('tools:updates', setUpdates),
      api().on('app:update', setAppUpdate),
      api().on('session:updated', (s) =>
        setSessions((list) => {
          const i = list.findIndex((x) => x.id === s.id)
          if (i === -1) return [s, ...list]
          const next = [...list]
          next[i] = s
          return next
        })
      )
    ]
    return () => offs.forEach((o) => o())
  }, [notify])

  // Refresh the tool list when installs finish.
  const running = jobs.some((j) => j.status === 'running')
  useEffect(() => {
    if (!running) void api().invoke('tools:list').then(setTools)
  }, [running])

  const value = useMemo<AppCtx>(
    () => ({ page, setPage, openSession, showSession, preset, setPreset, appInfo, settings, updateSettings, setSettings, sessions, setSessions, tools, setTools, jobs, updates, appUpdate, notices, dismiss, markRead, clearNotices, busy, act, notify }),
    [page, setPage, openSession, showSession, preset, appInfo, settings, updateSettings, sessions, tools, jobs, updates, appUpdate, notices, dismiss, markRead, clearNotices, busy, act, notify]
  )
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>
}

export function useApp(): AppCtx {
  const c = useContext(Ctx)
  if (!c) throw new Error('useApp outside AppProvider')
  return c
}
