import type { EncryptedStore } from '@sedecim/encrypted-store/browser';
import { browserEnvironment, CrashCapture, CrashReportStore, crashReportJson, type CrashReport, type CrashReportsMode, type StoredCrashReport } from '@sedecim/telemetry-policy/crash-report';
import { version } from '../../package.json';

/*
 * NFR007-03 (docs/crash-reports.md): failures of the web, captured as the active persona's profile says (its
 * `crashReports`). Locked, or with no persona, nothing is captured. No request is ever made: a report leaves the
 * browser only as a file the person saves.
 */

/** Collection of the browser vault (sealed with its master key, like every record in it) where opt-in reports live. */
export const CRASH_COLLECTION = 'crash-reports';

/** Where the global failures are heard: the window (an EventTarget in tests). */
export interface CrashEventTarget {
  addEventListener(type: string, listener: (event: Event) => void): void;
  removeEventListener(type: string, listener: (event: Event) => void): void;
}

/** The reports kept in this browser's vault (opt-in), with the retention of CRASH_RETENTION. */
export function crashStore(store: EncryptedStore): CrashReportStore {
  return new CrashReportStore(store.collection<StoredCrashReport>(CRASH_COLLECTION));
}

export class WebCrashReports {
  readonly capture: CrashCapture;
  private listening = false;

  constructor(
    private readonly target: CrashEventTarget | undefined,
    userAgent: string | undefined,
  ) {
    // The user agent is read here for its family and major version; the string itself is not kept.
    this.capture = new CrashCapture({ app: 'acceso-nostr-web', appVersion: version, environment: browserEnvironment(userAgent) });
  }

  private readonly onError = (event: Event) => {
    const e = event as ErrorEvent;
    // A script of another origin gives no error object: only the message and the position the event carries (and no
    // class: the record has no prototype, so the report says `_OTHER`).
    const thrown = e.error ?? Object.assign(Object.create(null) as object, { message: typeof e.message === 'string' ? e.message : '', stack: typeof e.filename === 'string' && e.filename ? `    at ${e.filename}:${e.lineno ?? 0}:${e.colno ?? 0}` : undefined });
    this.capture.capture(thrown, 'error');
  };

  private readonly onRejection = (event: Event) => {
    this.capture.capture((event as PromiseRejectionEvent).reason, 'unhandledrejection');
  };

  /**
   * The active persona's profile ('off' without one). The global listeners exist only while it captures; in 'opt-in'
   * each report also goes to the vault's store.
   */
  configure(c: { mode: CrashReportsMode | undefined; profile?: string; store?: EncryptedStore }): void {
    this.capture.configure({ mode: c.mode ?? 'off', ...(c.profile ? { profile: c.profile } : {}), ...(c.store ? { store: crashStore(c.store) } : {}) });
    const on = this.capture.currentMode !== 'off';
    if (!this.target || on === this.listening) return;
    const method = on ? 'addEventListener' : 'removeEventListener';
    this.target[method]('error', this.onError);
    this.target[method]('unhandledrejection', this.onRejection);
    this.listening = on;
  }

  /** A UI component failed (CrashBoundary): captured as the profile says, with React's component stack. */
  componentError(error: unknown, componentStack?: string | null): void {
    this.capture.capture(error, 'component', componentStack ? { componentStack } : {});
  }
}

let shared: WebCrashReports | undefined;

/** The page's instance, bound to the window the first time it is used. */
export function webCrashReports(): WebCrashReports {
  shared ??= new WebCrashReports(typeof window === 'undefined' ? undefined : window, typeof navigator === 'undefined' ? undefined : navigator.userAgent);
  return shared;
}

/** The file of a report: exactly the JSON the preview shows, saved by the browser's own download (no request). */
export function downloadCrashReport(report: CrashReport): void {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([crashReportJson(report)], { type: 'application/json' }));
  a.download = 'acceso-nostr-informe-de-fallo.json';
  a.click();
  URL.revokeObjectURL(a.href);
}
