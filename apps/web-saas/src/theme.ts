import { createTheme } from '@mui/material';

export const BRAND = 'Acceso Nostr';

// Follows the system light/dark preference, like acceso-frontend (mui-mode).
export const theme = createTheme({
  // Primary darkened from MUI's #1976d2 so text buttons on grey surfaces meet WCAG AA (4.5:1).
  colorSchemes: { light: { palette: { primary: { main: '#1565c0' } } }, dark: true },
  cssVariables: { colorSchemeSelector: 'media' },
  shape: { borderRadius: 8 },
  typography: { fontFamily: 'system-ui, -apple-system, "Segoe UI", Roboto, sans-serif' },
});
