import type { Platform, SovereigntyConfig, ValidationContext, ValidationIssue } from './types';
import { PRESENCE_TEXTS, presenceOption } from './presence';
import { vaultExpirationNotice } from './expiration';

const BANNED_CLAIMS = [
  /100\s*%\s*an[oó]nim/i,
  /totalmente an[oó]nim/i,
  /imposible de rastrear/i,
  /untraceable/i,
  // PANEL-06: deleting or expiring a message is a request that relays and contacts may ignore, never a guarantee.
  /borrado garantizado/i,
  /(borra|elimina|desaparece)\S* de todas partes/i,
  /guaranteed deletion/i,
];

/** Rejects absolute anonymity (and guaranteed deletion) claims in any UI copy (spec §2.2 "Privacidad explicable"). */
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
    // FR004-08: spec §14 keeps the key of this mode offline or in a signer; a key sealed on the connected device is said so.
    if (c.custody === 'local') warn('TOR_DEVICE_KEY', 'La llave de esta persona está en este dispositivo, cifrada con tu passphrase: quien comprometa el dispositivo y consiga la passphrase puede firmar como tú. Con un signer externo (NIP-46), la llave no está en este dispositivo.', ['custody', 'network']);
    if (c.telemetry !== 'none') err('TOR_TELEMETRY', 'En Tor-only la telemetría debe estar deshabilitada.', ['telemetry', 'network']);
    if (c.crashReports === 'opt-in') err('TOR_CRASH_REPORTS', 'En Tor-only el crash reporting debe estar deshabilitado o ser exportación manual local.', ['crashReports', 'network']);
    // FR015-05: a status says when the persona was active and what it wrote; Tor hides only where it came from.
    if (presenceOption(c) !== 'off') err('TOR_PRESENCE', PRESENCE_TEXTS.torOnly, ['presence', 'network']);
    // ADR 0010: no push at all in Tor-only, not even opaque — it ties the device to a push service and reveals activity times.
    if (c.notifications !== 'none') err('TOR_PUSH', 'En Tor-only no hay push (ni opaco): el servicio push y el gateway verían tu dispositivo y los tiempos de actividad. La app consulta los relays mientras está abierta.', ['notifications', 'network']);
    if (c.remotePreviews) err('TOR_PREVIEWS', 'Las previews remotas deben estar bloqueadas en Tor-only.', ['remotePreviews']);
    if (c.cloudBackup === 'operator-managed') err('TOR_CLOUD_BACKUP', 'En Tor-only el backup en la nube debe estar apagado o ser solo ciphertext con clave fuera del operador.', ['cloudBackup']);
    if (c.messaging === 'nip17') warn('TOR_NIP17_NO_FS', 'NIP-17 no ofrece forward secrecy: para conversaciones high-risk usa Marmot/MLS.', ['messaging']);
    if (c.files === 'relay-plain') err('TOR_PLAIN_FILES', 'En Tor-only los adjuntos deben cifrarse en el cliente.', ['files']);
    if (c.identity !== 'pseudonymous') warn('TOR_LINKED_IDENTITY', 'Vincular la identidad reduce el beneficio de Tor frente a correlación.', ['identity']);
    if (c.readReceipts) warn('TOR_READ_RECEIPTS', 'Las confirmaciones de lectura revelan patrones de actividad.', ['readReceipts']);
    if (c.deliveryReceipts) warn('TOR_DELIVERY_RECEIPTS', 'Las confirmaciones de entrega revelan cuándo está conectado tu dispositivo.', ['deliveryReceipts']);
    // PANEL-05: the residual risks of the high-risk profile (docs/threat-models/sovereign-tor.md), always shown.
    warn('TOR_EXPERIMENTAL', 'Perfil experimental: ni el cliente ni marmot-ts (alpha) han pasado una auditoría independiente. No lo trates todavía como apto para alto riesgo.', ['network']);
    warn('TOR_CORRELATION', 'Tor no te protege de quien observe a la vez tu conexión y la de los relays: puede correlacionar horarios y tamaños.', ['network']);
    warn('TOR_HABITS', 'Tu forma de escribir y tus horarios pueden identificarte; ninguna herramienta lo evita.', ['network']);
  } else if (c.identity === 'pseudonymous') {
    warn('NO_TOR_IP', 'Sin Tor, cada relay ve tu dirección IP y cuándo te conectas: esta persona es pseudónima, no anónima. Para alto riesgo usa el perfil sovereign-tor en el cliente soberano.', ['network', 'identity']);
  }
  if (c.localProtection === 'device') {
    if (c.custody !== 'local' || c.network !== 'direct' || c.identity !== 'linked')
      err('DEVICE_KEY_PROFILE', 'El desbloqueo sin contraseña solo se permite en el perfil convenience (llave local, red directa, identidad vinculada).', ['localProtection']);
    else warn('DEVICE_KEY', 'Sin contraseña: cualquiera con acceso a este perfil del navegador puede abrir tus llaves.', ['localProtection']);
  }
  // FR015-05: presence where the profile allows it (presencePolicy). An organization's policy cannot govern it yet, and
  // the institutional model denies what the policy does not govern; a pseudonymous persona is told what it risks.
  if (presenceOption(c) !== 'off' && c.network !== 'tor-only') {
    if (c.identity === 'verified') err('PRESENCE_ORGANIZATION', PRESENCE_TEXTS.organization, ['presence', 'identity']);
    else if (c.identity === 'pseudonymous') warn('PRESENCE_PSEUDONYMOUS', PRESENCE_TEXTS.pseudonymous, ['presence', 'identity']);
  }
  if (!c.stripFileMetadata) warn('FILES_METADATA', 'Las imágenes pueden contener ubicación (EXIF) y datos del dispositivo.', ['stripFileMetadata']);
  if (c.custody === 'managed' || c.custody === 'managed-enclave') warn('CUSTODIAL', 'Modo custodial: la plataforma puede firmar como el usuario. Requiere opt-in explícito.', ['custody']);
  if (c.quorum < 1) err('QUORUM', 'El quorum debe ser al menos 1.', ['quorum']);
  // FR010-04: with the persona's relays known, a quorum above them is refused instead of being capped in silence.
  if (ctx.relays !== undefined) {
    if (c.quorum > ctx.relays) err('QUORUM_RELAYS', `El quorum (${c.quorum}) supera los relays de esta persona (${ctx.relays}): lo que publiques en ellos nunca tendría ${c.quorum} aceptaciones. Baja el quorum o añade relays.`, ['quorum']);
  } else if (c.network === 'direct' && c.quorum > 1) warn('QUORUM_SINGLE', 'Quorum > 1 requiere varios relays configurados.', ['quorum', 'network']);
  if (c.persistence === 'device' && c.cloudBackup === 'off' && c.custody !== 'offline') warn('LOSS_RISK', 'Sin backup ni replicación: perder el dispositivo implica perder historial y, posiblemente, la identidad.', ['persistence', 'cloudBackup']);
  // VAULT-04: the Continuity Vault is a cloud copy, and `required-for-resilient` needs one to send at all.
  const continuity = c.continuity ?? 'off';
  if (continuity !== 'off') {
    if (c.cloudBackup === 'off') err('CONTINUITY_CLOUD_OFF', 'Con el backup en la nube apagado no se usa el Continuity Vault: pon la continuidad en off o enciende el backup en la nube.', ['continuity', 'cloudBackup']);
    if (ctx.continuityVault === false) {
      if (continuity === 'required-for-resilient') err('CONTINUITY_NO_VAULT', 'Esta persona exige una copia en el Continuity Vault antes de enviar, pero no hay vault configurado: todos los envíos quedarían retenidos.', ['continuity']);
      else warn('CONTINUITY_NO_VAULT', 'No hay Continuity Vault configurado: los envíos salen, pero sin copia en el vault.', ['continuity']);
    }
  }
  // PANEL-06: the vault keeps its copies with its own retention, which may outlast the expiration of the messages.
  const outlives = c.messageExpiration ? vaultExpirationNotice(c.messageExpiration, { cloudBackup: c.cloudBackup, continuityVault: ctx.continuityVault, retentionDays: ctx.vaultRetentionDays }) : undefined;
  if (outlives) warn('EXPIRATION_VAULT', outlives, ['messageExpiration', 'cloudBackup']);
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
