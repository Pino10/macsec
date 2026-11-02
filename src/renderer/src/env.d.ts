/// <reference types="vite/client" />
import type { MacSecApi } from '@shared/types'

declare global {
  interface Window {
    macsec: MacSecApi
  }
}

export {}
