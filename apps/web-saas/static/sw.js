// Push service worker (ADR 0010). Pushes are opaque: the payload is never read and the notification
// always shows the same generic text, so nothing about content, sender or count reaches the screen.
// Registered per persona under ./push/<persona>/ (one push endpoint per persona). Same-origin script:
// allowed by the CSP `script-src 'self'` (worker-src falls back to it).
self.addEventListener('push', (event) => {
  event.waitUntil(
    self.registration.showNotification('Acceso Nostr', {
      body: 'Tienes actividad nueva',
      tag: 'acceso-nostr-activity',
      renotify: false,
    }),
  );
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const app = new URL('./', self.location.href).href;
  event.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((list) => {
      const open = list.find((c) => c.url.startsWith(app));
      return open ? open.focus() : self.clients.openWindow(app);
    }),
  );
});

// The gateway registration needs a NIP-98 signature from the persona, which this worker does not have:
// the app re-registers the new subscription the next time the persona is opened.
self.addEventListener('pushsubscriptionchange', () => {});
