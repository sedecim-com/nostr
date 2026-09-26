import { DEFAULT_TIMESTAMP_JITTER_SECONDS, type WrapOptions } from './nip59';

/** Bounded gift-wrap jitter of the Buzz adapter while upstream issue #4192 stays open (±5 min). */
export const BUZZ_ADAPTER_JITTER_SECONDS = 300;

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

export interface Nip17StrategyResult {
  accepted: number;
  attempts: number;
  messages?: string[];
}

/**
 * FR017-05: NIP-17 decision of the interop gate, re-run on every Buzz sync (ci.yml and the monthly
 * buzz-upstream pin PR). The standard NIP-59 jitter (2 days) wins as soon as the relay accepts every
 * attempt with it, i.e. once upstream #4192 is fixed; otherwise the bounded adapter; otherwise NIP-17
 * stays off. Enabling also requires that the recipient received and opened the wraps.
 */
export function nip17GateDecision(strategies: Record<string, Nip17StrategyResult | undefined>, receivedByRecipient: number): { recommendedJitterSeconds: number | null; enableFlag: boolean } {
  const passes = (name: string) => {
    const r = strategies[name];
    return !!r && r.attempts > 0 && r.accepted === r.attempts;
  };
  const recommendedJitterSeconds = passes('nip59-default-2d') ? DEFAULT_TIMESTAMP_JITTER_SECONDS : passes('bounded-5m') ? BUZZ_ADAPTER_JITTER_SECONDS : null;
  return { recommendedJitterSeconds, enableFlag: receivedByRecipient > 0 && recommendedJitterSeconds !== null };
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

const describeNip17 = (f: DeploymentFlags['nip17'] | undefined) => (!f?.enabled ? 'NIP-17 deshabilitado' : `jitter ${f.timestampJitterSeconds} s`);

/**
 * One-line summary (Spanish, for the pin PR body) of how the gate changed the NIP-17 flags between the
 * committed flags and the regenerated ones; undefined when nothing changed.
 */
export function nip17FlagsChange(before: DeploymentFlags | undefined, after: DeploymentFlags): string | undefined {
  const b = before?.nip17;
  const a = after.nip17;
  if (b?.enabled === a.enabled && b?.timestampJitterSeconds === a.timestampJitterSeconds) return undefined;
  const std = DEFAULT_TIMESTAMP_JITTER_SECONDS;
  if (a.enabled && a.timestampJitterSeconds === std)
    return `#4192 resuelto upstream: se vuelve al jitter estándar de NIP-59 (${std} s, antes: ${describeNip17(b)}). Revisar si se retira el adaptador BUZZ_PINNED_ADAPTER.wrap (FR017-05).`;
  if (b?.enabled && b.timestampJitterSeconds === std && a.enabled && a.timestampJitterSeconds === BUZZ_ADAPTER_JITTER_SECONDS)
    return `Regresión de #4192: el relay vuelve a rechazar el jitter estándar; se usa el adaptador de ${BUZZ_ADAPTER_JITTER_SECONDS} s.`;
  return `Cambian los flags NIP-17: ${describeNip17(b)} → ${describeNip17(a)}.`;
}
