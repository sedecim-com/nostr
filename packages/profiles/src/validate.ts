import type { Platform, SovereigntyConfig, ValidationContext, ValidationIssue } from './types';

const BANNED_CLAIMS = [/100\s*%\s*an[oó]nim/i, /totalmente an[oó]nim/i, /imposible de rastrear/i, /untraceable/i];

/** Rejects absolute anonymity marketing claims in any UI copy (spec §2.2 "Privacidad explicable"). */
export function assertNoAbsoluteClaims(text: string): void {
  for (const re of BANNED_CLAIMS) if (re.test(text)) throw new Error(`absolute privacy claim not allowed: "${text}"`);
}

export function validateConfig(c: SovereigntyConfig, platform: Platform = 'desktop', ctx: ValidationContext = {}): ValidationIssue[] {
  const issues: ValidationIssue[] = [];
  const err = (code: string, message: string, controls: Array<keyof SovereigntyConfig>) => issues.push({ severity: 'error', code, message, controls });
  const warn = (code: string, message: string, controls: Array<keyof SovereigntyConfig>) => issues.push({ severity: 'warning', code, message, controls });

  if (c.network === 'tor-only') {
    if (platform === 'web') err('TOR_WEB_UNSUPPORTED', 'Tor-only no puede garantizarse desde un navegador estándar: usa el cliente soberano dedicado.', ['network']);
    if (c.custody === 'managed' || c.custody === 'managed-enclave') err('TOR_MANAGED_KEY', 'Sovereign Tor Mode no admite custodia managed: el Key Service no debe existir en este modo.', ['custody', 'network']);
    if (c.telemetry !== 'none') err('TOR_TELEMETRY', 'En Tor-only la telemetría debe estar deshabilitada.', ['telemetry', 'network']);
    if (c.crashReports === 'opt-in') err('TOR_CRASH_REPORTS', 'En Tor-only el crash reporting debe estar deshabilitado o ser exportación manual local.', ['crashReports', 'network']);
    // ADR 0010: no push at all in Tor-only, not even opaque — it ties the device to a push service and reveals activity times.
    if (c.notifications !== 'none') err('TOR_PUSH', 'En Tor-only no hay push (ni opaco): el servicio push y el gateway verían tu dispositivo y los tiempos de actividad. La app consulta los relays mientras está abierta.', ['notifications', 'network']);
    if (c.remotePreviews) err('TOR_PREVIEWS', 'Las previews remotas deben estar bloqueadas en Tor-only.', ['remotePreviews']);
    if (c.cloudBackup === 'operator-managed') err('TOR_CLOUD_BACKUP', 'En Tor-only el backup en la nube debe estar apagado o ser solo ciphertext con clave fuera del operador.', ['cloudBackup']);
    if (c.messaging === 'nip17') warn('TOR_NIP17_NO_FS', 'NIP-17 no ofrece forward secrecy: para conversaciones high-risk usa Marmot/MLS.', ['messaging']);
    if (c.files === 'relay-plain') err('TOR_PLAIN_FILES', 'En Tor-only los adjuntos deben cifrarse en el cliente.', ['files']);
    if (c.identity !== 'pseudonymous') warn('TOR_LINKED_IDENTITY', 'Vincular la identidad reduce el beneficio de Tor frente a correlación.', ['identity']);
    if (c.readReceipts) warn('TOR_READ_RECEIPTS', 'Las confirmaciones de lectura revelan patrones de actividad.', ['readReceipts']);
    if (c.deliveryReceipts) warn('TOR_DELIVERY_RECEIPTS', 'Las confirmaciones de entrega revelan cuándo está conectado tu dispositivo.', ['deliveryReceipts']);
  }
  if (c.localProtection === 'device') {
    if (c.custody !== 'local' || c.network !== 'direct' || c.identity !== 'linked')
      err('DEVICE_KEY_PROFILE', 'El desbloqueo sin contraseña solo se permite en el perfil convenience (llave local, red directa, identidad vinculada).', ['localProtection']);
    else warn('DEVICE_KEY', 'Sin contraseña: cualquiera con acceso a este perfil del navegador puede abrir tus llaves.', ['localProtection']);
  }
  if (!c.stripFileMetadata) warn('FILES_METADATA', 'Las imágenes pueden contener ubicación (EXIF) y datos del dispositivo.', ['stripFileMetadata']);
  if (c.custody === 'managed' || c.custody === 'managed-enclave') warn('CUSTODIAL', 'Modo custodial: la plataforma puede firmar como el usuario. Requiere opt-in explícito.', ['custody']);
  if (c.quorum < 1) err('QUORUM', 'El quorum debe ser al menos 1.', ['quorum']);
  // FR010-04: with the persona's relays known, a quorum above them is refused instead of being capped in silence.
  if (ctx.relays !== undefined) {
    if (c.quorum > ctx.relays) err('QUORUM_RELAYS', `El quorum (${c.quorum}) supera los relays de esta persona (${ctx.relays}): lo que publiques en ellos nunca tendría ${c.quorum} aceptaciones. Baja el quorum o añade relays.`, ['quorum']);
  } else if (c.network === 'direct' && c.quorum > 1) warn('QUORUM_SINGLE', 'Quorum > 1 requiere varios relays configurados.', ['quorum', 'network']);
  if (c.persistence === 'device' && c.cloudBackup === 'off' && c.custody !== 'offline') warn('LOSS_RISK', 'Sin backup ni replicación: perder el dispositivo implica perder historial y, posiblemente, la identidad.', ['persistence', 'cloudBackup']);
  return issues;
}

export function isValid(c: SovereigntyConfig, platform?: Platform, ctx?: ValidationContext): boolean {
  return !validateConfig(c, platform, ctx).some((i) => i.severity === 'error');
}

export interface ReceiptPolicy {
  delivered: boolean;
  read: boolean;
}

/** Which receipts the client may send for a configuration (ADR 0005). Read receipts are never implicit. */
export function receiptPolicy(c: SovereigntyConfig): ReceiptPolicy {
  return { delivered: c.deliveryReceipts, read: c.readReceipts };
}
