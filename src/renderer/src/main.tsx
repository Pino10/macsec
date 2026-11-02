import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import '@fontsource/poppins/300.css'
import '@fontsource/poppins/400.css'
import '@fontsource/poppins/500.css'
import '@fontsource/poppins/600.css'
import '@fontsource/poppins/700.css'
import '@fontsource/ibm-plex-mono/400.css'
import './macsec.css'
import App from './App'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>
)
