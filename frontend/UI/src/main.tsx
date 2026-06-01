import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import App from './App'
import './styles/globals.css'

/*
 * StrictMode is intentionally removed.
 *
 * React 18 StrictMode double-invokes every useEffect in development — it mounts,
 * cleans up, and remounts each effect to surface missing cleanup functions. While
 * useful for library authors, this makes async-loading UI elements (GIS button,
 * AuthContext /auth/me/ call, ResizeObserver) visibly flash on every page load in
 * dev mode, giving a false impression of a production bug.
 *
 * All production-facing flicker sources have been addressed separately:
 *   - FOUC: inline body background in index.html
 *   - GIS layout shift: minHeight reserved on the button wrapper
 *   - Font FOUT: display=fallback on Google Fonts URL
 *
 * Re-add StrictMode here if you want React's double-invoke checks during a
 * dedicated audit pass — just be aware it will reintroduce the dev-mode flickers.
 */
createRoot(document.getElementById('root')!).render(
  <BrowserRouter>
    <App />
  </BrowserRouter>,
)
