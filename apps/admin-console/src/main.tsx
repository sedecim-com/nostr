import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import createCache from '@emotion/cache';
import { CacheProvider } from '@emotion/react';
import { CssBaseline, ThemeProvider, createTheme } from '@mui/material';
import { App } from './App';

// Styles are injected with the per-request CSP nonce: the policy never needs 'unsafe-inline'.
const nonce = document.querySelector<HTMLMetaElement>('meta[name=csp-nonce]')?.content;
const cache = createCache({ key: 'ac', ...(nonce ? { nonce } : {}) });

// Palette of apps/web-saas; warning/info are darkened too so filled status chips meet WCAG AA (4.5:1).
const theme = createTheme({
  colorSchemes: { light: { palette: { primary: { main: '#1565c0' }, warning: { main: '#b45309' }, info: { main: '#0277bd' } } }, dark: true },
  cssVariables: { colorSchemeSelector: 'media' },
  shape: { borderRadius: 8 },
  typography: { fontFamily: 'system-ui, -apple-system, "Segoe UI", Roboto, sans-serif' },
});

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <CacheProvider value={cache}>
      <ThemeProvider theme={theme}>
        <CssBaseline />
        <App />
      </ThemeProvider>
    </CacheProvider>
  </StrictMode>,
);
