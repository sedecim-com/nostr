import type { WrapOptions } from './nip59';

/** Deployment messaging flags derived from the interop gate (FR-017). Served as flags.json. */
export interface DeploymentFlags {
  nip17: { enabled: boolean; timestampJitterSeconds: number | null };
  relay: string;
  source: string;
  generatedAt: string;
}

interface InteropReport {
  relay?: string;
  finishedAt?: string;
  nip17?: { enableFlag?: boolean; recommendedJitterSeconds?: number | null };
}

/** NIP-17 is enabled only when the gate says so, with the jitter it measured as accepted. */
export function flagsFromInteropReport(report: InteropReport, relay: string, source: string): DeploymentFlags {
  const enabled = report.nip17?.enableFlag === true && typeof report.nip17.recommendedJitterSeconds === 'number';
  return {
    nip17: { enabled, timestampJitterSeconds: enabled ? report.nip17!.recommendedJitterSeconds! : null },
    relay,
    source,
    generatedAt: report.finishedAt ?? new Date().toISOString(),
  };
}

/** Wrap options for the deployment: the gate's jitter, or the adapter's default when flags are absent. */
export function wrapOptionsFromFlags(flags: DeploymentFlags | undefined, fallback: WrapOptions): WrapOptions {
  const j = flags?.nip17.timestampJitterSeconds;
  return typeof j === 'number' ? { ...fallback, timestampJitterSeconds: j } : fallback;
}
