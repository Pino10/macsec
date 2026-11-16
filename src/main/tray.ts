/**
 * MacSec in the menu bar: the posture score and any running test, so a long scan is not invisible
 * once the window is hidden. It only shows things and opens the window: nothing runs from here.
 */
import { Menu, Tray, nativeImage, type MenuItemConstructorOptions } from 'electron'
import type { SessionInfo } from '../shared/types'
import { trayModel } from './traymodel'

const ICON = 'iVBORw0KGgoAAAANSUhEUgAAACQAAAAkCAYAAADhAJiYAAADuUlEQVR4Xs2XSaiOYRTHf2aReWFcyJShZEqmBQtEGUpsZEFJVhJ2ipViIxsZUspKlIUFJSuxMZRhgRCZMiSkzEP/r3O+zn3u877fe333xr++uO/7nPP8z/8Mz/PCf4ZOTfLpDDUfv8yP/hb09+8mfVeGCHQ1ImXQGidYGVUV0jp3/jN4nwCsBcYCb4C+wEHgKtTXRRWbVk3OuiThDQbWA+eBL5YabRR/N4BtwPjEVr70qypEHamR5F8IHAOeJZt/Bc4CR4H3ybtPwBlgHdAnISeflRDZTwR2AbczSuiZ3mmNYwSwEbiUUe8xcBiYE1RvqJTXyTLgQsap1JFKUitGKMdpaicD+4A7mWBuAVssikJSXnxjgM/BierknNWN6idCJGInObG4SQ9gOXAceJeQW23O0mBq8IeLzOgbsB9qnZSSqFKYIprWyXBgs9XaD2CPOc7WkxOaHwbbjGBQNnukSJH0rppvKqKvLOidKaEcs+i8v6VELR3nj8Pnk7+Lk9rhtr52YCDfanC2epBAG/mxkINv1gtq5LVWvyK19C4XWB2NCBXBN+xndXYXeAicBsZZOhq2dA6Vh1MCr4tTNgIcq4B5wDTgpSnVpuOikUK5KFX8kn6pkVE3+umuqa3RsN1UyrVzqXI5hWJE3zOyusPZRkRBeWDyJ3IzzS5Xf2p3f95KvZxCMaqRJnsuqgehAx1e0E/sQbTz/w8J51q3wioNnaHz6INJrkNTSKexnKurHtk6Ra2fn/jTM3aeDd0CfN0KW5ed1IK/OGFGOq1110lJOcEpwJWwgQ7QNZn1HnB3qJ1jUvIe0LMkAy0ILQmb7LAN0nrzFOhf1cwCoHcBGQ90VmiAvQV+W8A30c3vhRlLgXhjjGhUgw4PRiSULikkcjErhfBojpihTn7deXK3R09F2U3QZ5bSozSJzE2opa/S8HRCSoNHc8DoqysqOQnwTloZykBzSqg8mLWpIrhsTqTSJnNSlL4U8dI21ya3AnwLjC4pgyz8sjYKuB8iOxSiKmxVS68rqUD8wvcR6q3e6JRoBTcYZF8YPjt0Xx5aIrkTVToUgNvpAPYJXhZMKWIUuj2686fAYrN0NWNNaHaJuK/XJ5MCq9RVjRBrYUP41FG3bA3GXqAi+jqQUSCOv1YmB99QV4trYUN9hfhAFEE/+VW8cWq3tTsrwUkNAE4GUheTerkOTC2ps3ZFlH135ptLREU41lSHI9aV0vIcahc1fcl2SL1UhadwGDDJjGLX/RPEFLZrFzWDeI1tCn8A4SPg3Oh9+2oAAAAASUVORK5CYII='

let tray: Tray | null = null

export function startTray(o: { sessions: () => SessionInfo[]; show: (session?: string) => void; newTest: () => void; quit: () => void }): () => void {
  const icon = nativeImage.createFromBuffer(Buffer.from(ICON, 'base64'), { scaleFactor: 2 })
  icon.setTemplateImage(true)
  tray = new Tray(icon)
  tray.setToolTip('MacSec')
  let timer: NodeJS.Timeout | null = null
  const rebuild = (): void => {
    if (!tray) return
    const m = trayModel(o.sessions())
    if (process.platform === 'darwin') tray.setTitle(m.title)
    const items: MenuItemConstructorOptions[] = [
      ...m.lines.map((l): MenuItemConstructorOptions => (l.session ? { label: l.label, click: () => o.show(l.session) } : { label: l.label, enabled: false })),
      { type: 'separator' },
      { label: 'Open MacSec', click: () => o.show() },
      { label: 'New test', click: () => o.newTest() },
      { type: 'separator' },
      { label: 'Quit MacSec', click: () => o.quit() }
    ]
    tray.setContextMenu(Menu.buildFromTemplate(items))
  }
  rebuild()
  // Sessions change many times a second while a scan runs: redraw at most once a second.
  return () => {
    if (timer) return
    timer = setTimeout(() => {
      timer = null
      rebuild()
    }, 1000)
  }
}
