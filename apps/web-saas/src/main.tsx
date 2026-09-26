import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import createCache from '@emotion/cache';
import { CacheProvider } from '@emotion/react';
import { CssBaseline, ThemeProvider } from '@mui/material';
import { App } from './App';
import { theme } from './theme';

// Styles are injected with the per-request CSP nonce: the policy never needs 'unsafe-inline'.
const nonce = document.querySelector<HTMLMetaElement>('meta[name=csp-nonce]')?.content;
const cache = createCache({ key: 'an', ...(nonce ? { nonce } : {}) });

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
