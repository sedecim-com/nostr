import type { Platform, SovereigntyConfig, ValidationIssue } from './types';

const BANNED_CLAIMS = [/100\s*%\s*an[oó]nim/i, /totalmente an[oó]nim/i, /imposible de rastrear/i, /untraceable/i];

/** Rejects absolute anonymity marketing claims in any UI copy (spec §2.2 "Privacidad explicable"). */
export function assertNoAbsoluteClaims(text: string): void {
  for (const re of BANNED_CLAIMS) if (re.test(text)) throw new Error(`absolute privacy claim not allowed: "${text}"`);
}

export function validateConfig(c: SovereigntyConfig, platform: Platform = 'desktop'): ValidationIssue[] {
  const issues: ValidationIssue[] = [];
  const err = (code: string, message: string, controls: Array<keyof SovereigntyConfig>) => issues.push({ severity: 'error', code, message, controls });
  const warn = (code: string, message: string, controls: Array<keyof SovereigntyConfig>) => issues.push({ severity: 'warning', code, message, controls });

  if (c.network === 'tor-only') {
    if (platform === 'web') err('TOR_WEB_UNSUPPORTED', 'Tor-only no puede garantizarse desde un navegador estándar: usa el cliente soberano dedicado.', ['network']);
    if (c.custody === 'managed' || c.custody === 'managed-enclave') err('TOR_MANAGED_KEY', 'Sovereign Tor Mode no admite custodia managed: el Key Service no debe existir en este modo.', ['custody', 'network']);
    if (c.telemetry !== 'none') err('TOR_TELEMETRY', 'En Tor-only la telemetría debe estar deshabilitada.', ['telemetry', 'network']);
    if (c.crashReports === 'opt-in') err('TOR_CRASH_REPORTS', 'En Tor-only el crash reporting debe estar deshabilitado o ser exportación manual local.', ['crashReports', 'network']);
    if (c.notifications === 'push') err('TOR_PUSH', 'Push convencional revela metadatos a APNs/FCM: deshabilitado en Tor-only.', ['notifications', 'network']);
    if (c.notifications === 'privacy-push') warn('TOR_PRIVACY_PUSH', 'Incluso el push opaco revela tiempos de actividad.', ['notifications']);
    if (c.remotePreviews) err('TOR_PREVIEWS', 'Las previews remotas deben estar bloqueadas en Tor-only.', ['remotePreviews']);
    if (c.cloudBackup === 'operator-managed') err('TOR_CLOUD_BACKUP', 'En Tor-only el backup en la nube debe estar apagado o ser solo ciphertext con clave fuera del operador.', ['cloudBackup']);
    if (c.messaging === 'nip17') warn('TOR_NIP17_NO_FS', 'NIP-17 no ofrece forward secrecy: para conversaciones high-risk usa Marmot/MLS.', ['messaging']);
    if (c.files === 'relay-plain') err('TOR_PLAIN_FILES', 'En Tor-only los adjuntos deben cifrarse en el cliente.', ['files']);
    if (c.identity !== 'pseudonymous') warn('TOR_LINKED_IDENTITY', 'Vincular la identidad reduce el beneficio de Tor frente a correlación.', ['identity']);
    if (c.readReceipts) warn('TOR_READ_RECEIPTS', 'Las confirmaciones de lectura revelan patrones de actividad.', ['readReceipts']);
  }
  if (!c.stripFileMetadata) warn('FILES_METADATA', 'Las imágenes pueden contener ubicación (EXIF) y datos del dispositivo.', ['stripFileMetadata']);
  if (c.custody === 'managed' || c.custody === 'managed-enclave') warn('CUSTODIAL', 'Modo custodial: la plataforma puede firmar como el usuario. Requiere opt-in explícito.', ['custody']);
  if (c.quorum < 1) err('QUORUM', 'El quorum debe ser al menos 1.', ['quorum']);
  if (c.network === 'direct' && c.quorum > 1) warn('QUORUM_SINGLE', 'Quorum > 1 requiere varios relays configurados.', ['quorum', 'network']);
  if (c.persistence === 'device' && c.cloudBackup === 'off' && c.custody !== 'offline') warn('LOSS_RISK', 'Sin backup ni replicación: perder el dispositivo implica perder historial y, posiblemente, la identidad.', ['persistence', 'cloudBackup']);
  return issues;
}

export function isValid(c: SovereigntyConfig, platform?: Platform): boolean {
  return !validateConfig(c, platform).some((i) => i.severity === 'error');
}
