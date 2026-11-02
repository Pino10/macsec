import { contextBridge, ipcRenderer } from 'electron'
import type { Events, MacSecApi } from '../shared/types'

const api: MacSecApi = {
  invoke: (channel, ...args) => ipcRenderer.invoke(channel, ...args),
  on: <K extends keyof Events>(event: K, cb: (payload: Events[K]) => void) => {
    const handler = (_: unknown, payload: Events[K]): void => cb(payload)
    ipcRenderer.on(event, handler)
    return () => ipcRenderer.removeListener(event, handler)
  },
  platform: process.platform
}

contextBridge.exposeInMainWorld('macsec', api)
