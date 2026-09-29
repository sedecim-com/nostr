import type { Dimension, Disclosure, SovereigntyConfig } from './types';
import { PRESETS } from './presets';

type Entry = Omit<Disclosure, 'control' | 'option'>;
const d = (statement: string, improves: Dimension[], sacrifices: Dimension[], trustAssumptions: string[] = []): Entry => ({ statement, improves, sacrifices, trustAssumptions });

const CATALOG: { [K in keyof SovereigntyConfig]?: Record<string, Entry> } = {
  custody: {
    local: d('La llave se genera y guarda cifrada en este dispositivo. La plataforma no puede firmar ni recuperar tu llave.', ['soberania', 'privacidad-operador'], ['recuperabilidad'], ['Seguridad del dispositivo y de tu passphrase.']),
    offline: d('La llave vive fuera de línea (air-gapped/hardware). Nadie más puede firmar; la recuperación es tu responsabilidad.', ['soberania', 'privacidad-operador'], ['recuperabilidad'], ['Custodia física del respaldo.']),
    external: d('Un signer externo (NIP-46/NIP-07) firma por ti; este cliente nunca ve la nsec.', ['soberania', 'privacidad-operador'], [], ['El signer externo y los permisos que le concedas.']),
    'encrypted-backup': d('El operador almacena un backup cifrado con una clave que solo tú controlas: guarda ciphertext, no la clave de descifrado.', ['recuperabilidad'], [], ['Fortaleza de tu contraseña de backup (scrypt).']),
    managed: d('Managed Key activado: la plataforma tiene capacidad técnica de firmar como tú y descifra en su servidor tus mensajes directos (NIP-44). Este modo es CUSTODIAL.', ['recuperabilidad', 'control-institucional'], ['soberania', 'privacidad-operador'], ['Operador, su vault (Secrets Manager/KMS) y su personal.']),
    'managed-enclave': d('Custodia en enclave: el backend general no ve la llave en claro, pero el servicio de firma sí puede firmar como tú. Sigue siendo CUSTODIAL.', ['recuperabilidad', 'control-institucional'], ['soberania'], ['Attestation del enclave y políticas KMS del operador.']),
  },
  network: {
    direct: d('Conexión directa: cada relay ve tu dirección IP y cuándo te conectas.', [], ['privacidad-operador'], ['Operadores de relay e ISP.']),
    'private-relay': d('Relay privado con NIP-42: solo miembros autenticados leen/publican; el operador del relay ve IP y metadatos.', ['control-institucional'], [], ['Operador del relay privado.']),
    'multi-relay': d('Publicación en varios relays con quorum: más disponibilidad, pero más operadores observan tus metadatos.', ['recuperabilidad'], ['privacidad-operador'], ['Todos los relays configurados.']),
    'tor-only': d('Tor-only: no se permite fallback clearnet. Si Tor no está disponible, el mensaje queda en outbox sin enviarse.', ['privacidad-operador', 'soberania'], ['recuperabilidad'], ['Red Tor; ausencia de fugas en este cliente (verificado por tests de fugas).']),
  },
  identity: {
    pseudonymous: d('Identidad pseudónima: la app no vincula esta persona con otras ni con datos reales.', ['privacidad-operador'], [], []),
    linked: d('Identidad vinculada a tu cuenta: el servicio de identidad conoce la relación cuenta↔npub.', ['recuperabilidad'], ['privacidad-operador'], ['Servicio de identidad del operador.']),
    verified: d('Identidad verificada por la organización: tu npub queda asociado a tu cargo en el directorio.', ['control-institucional'], ['privacidad-operador'], ['Organización y su directorio.']),
  },
  persistence: {
    device: d('Solo en el dispositivo: perder el dispositivo sin backup implica perder el historial.', ['soberania', 'privacidad-operador'], ['recuperabilidad'], []),
    relay: d('Persistencia en el relay: la disponibilidad depende de ese relay y de su política de retención.', ['recuperabilidad'], [], ['Operador del relay.']),
    replicated: d('Replicado en varios relays / mirror: menor riesgo de pérdida, mayor superficie de confianza.', ['recuperabilidad'], ['privacidad-operador'], ['Relays y mirror configurados.']),
    'encrypted-cloud': d('Copia en la nube cifrada en el cliente: el operador guarda ciphertext.', ['recuperabilidad'], [], ['Gestión de la clave de cifrado por el usuario.']),
  },
  messaging: {
    nip17: d('DMs NIP-17 (NIP-44 + gift wrap): el relay no ve el contenido ni el remitente, pero NO hay forward secrecy ni post-compromise security.', ['privacidad-operador'], [], ['Confidencialidad a largo plazo de tu nsec.']),
    marmot: d('Grupos Marmot/MLS: forward secrecy y post-compromise security, con menor compatibilidad con clientes Nostr genéricos.', ['privacidad-operador'], [], ['La implementación Marmot/MLS (marmot-ts, versión fijada y todavía sin auditoría independiente).']),
  },
  files: {
    'relay-plain': d('Archivos sin cifrar en Blossom: el operador del almacenamiento puede ver el contenido.', [], ['privacidad-operador'], ['Operador del servidor Blossom.']),
    'client-encrypted': d('Archivos cifrados antes de subir: el servidor Blossom solo ve un blob cifrado y su hash.', ['privacidad-operador'], [], []),
  },
  telemetry: {
    standard: d('Telemetría estándar: esta versión no envía trazas ni telemetría de uso desde el cliente.', [], [], []),
    minimal: d('Telemetría mínima: esta versión no envía telemetría desde el cliente.', [], [], []),
    none: d('Sin telemetría: no se emite ninguna llamada de analytics ni crash reporting.', ['privacidad-operador'], [], []),
  },
  notifications: {
    push: d('Push opaco: el aviso no lleva contenido, remitente ni recuento y sale agrupado con un retardo aleatorio. El servicio push del navegador o del sistema ve cuándo llega un aviso a tu dispositivo; el gateway de notificaciones sabe qué npub vigila para ese dispositivo.', [], ['privacidad-operador'], ['Servicio push (Apple/Google/Mozilla) y operador del gateway de notificaciones.']),
    'privacy-push': d('Push de solo aviso de actividad: sin contenido, remitente ni recuento, agrupado con un retardo aleatorio largo que difumina los tiempos. El gateway de notificaciones sigue sabiendo qué npub vigila para tu dispositivo.', [], ['privacidad-operador'], ['Servicio push (metadatos de tiempo) y operador del gateway de notificaciones.']),
    none: d('Sin notificaciones push: nada se revela a servicios push ni al gateway; la app consulta los relays solo mientras está abierta.', ['privacidad-operador'], [], []),
  },
  cloudBackup: {
    off: d('Sin backup en la nube.', ['privacidad-operador'], ['recuperabilidad'], []),
    'ciphertext-user-key': d('Backup en la nube cifrado con clave del usuario: el operador almacena ciphertext pero no la clave de descifrado.', ['recuperabilidad'], [], ['Tu contraseña de backup.']),
    'operator-managed': d('Backup gestionado por el operador: el operador puede restaurar (y por tanto acceder a) los datos.', ['recuperabilidad', 'control-institucional'], ['privacidad-operador', 'soberania'], ['Operador.']),
  },
  continuity: {
    off: d('Sin copia automática en el Continuity Vault: tu historial depende de los relays y de este dispositivo, salvo lo que guardes a mano en el vault.', ['privacidad-operador'], ['recuperabilidad'], []),
    'best-effort': d('Cada evento que envías se copia cifrado en el Continuity Vault, aparte de los relays. Si el vault no responde, el envío sale igual y la copia se reintenta. El operador del vault ve cuándo envías y cuántos eventos, no su contenido.', ['recuperabilidad'], ['privacidad-operador'], ['Operador del vault (ve la cuenta, el tamaño y la hora de cada copia).']),
    'required-for-resilient': d('Ningún evento sale hacia los relays hasta que su copia cifrada está en el Continuity Vault: si el vault no responde, el envío queda retenido hasta que responda. El operador del vault ve cuándo envías y cuántos eventos, no su contenido.', ['recuperabilidad'], ['privacidad-operador', 'soberania'], ['Operador del vault (ve la cuenta, el tamaño y la hora de cada copia, y su disponibilidad decide cuándo sale cada envío).']),
  },
  localProtection: {
    passphrase: d('El almacén local se abre con tu contraseña (scrypt): sin ella, nadie con acceso a este dispositivo puede leer tus llaves.', ['soberania', 'privacidad-operador'], ['recuperabilidad'], ['Fortaleza de tu contraseña local.']),
    device: d('Desbloqueo sin contraseña con una llave del dispositivo (WebCrypto, no exportable): cualquiera con acceso a este perfil del navegador puede abrir tus llaves.', [], ['soberania', 'privacidad-operador'], ['Seguridad física y de la sesión de este dispositivo.']),
  },
  crashReports: {
    off: d('Sin informes de fallo: esta versión no los genera.', ['privacidad-operador'], [], []),
    'manual-export': d('Informes de fallo exportables a mano: todavía no existen; esta versión no genera ninguno.', [], [], []),
    'opt-in': d('Informes de fallo opt-in: todavía no existen; esta versión no envía ninguno.', [], [], []),
  },
};

/**
 * Version of the disclosure copy under legal/UX review (FR028-02). Any change to a statement must bump it:
 * docs/disclosures.md is generated from disclosureCatalog() and CI fails if it is stale.
 */
export const DISCLOSURE_VERSION = '1.7.0';

/**
 * FR005-08: what someone accepts, besides the managed custody statement, to create a managed (custodial) key.
 * Part of the reviewed copy (disclosureCatalog, docs/disclosures.md): the consent recorded with the key names
 * DISCLOSURE_VERSION (see managedConsentVersion).
 */
export const MANAGED_CONSENT_TEXTS = {
  decryption: 'Tus mensajes directos (NIP-44) se cifran y descifran en el servidor de firma: el servicio ve su contenido en claro mientras lo procesa, aunque no lo guarda.',
  storage: 'La llave se guarda cifrada con AWS KMS en us-east-1 (LFPDPPP). Puedes migrarla a custodia local cuando quieras; tras borrarla se destruye a los 30 días.',
  accept: 'Entiendo que la plataforma puede firmar como yo y descifrar mis mensajes directos, y acepto la custodia gestionada',
} as const;

/**
 * VAULT-07 (ADR 0011): what the Continuity Vault keeps and what its operator can see, shown by the web and the
 * CLI wherever the vault is used. Part of the reviewed copy (disclosureCatalog, docs/disclosures.md).
 */
export const CONTINUITY_VAULT_TEXTS = {
  what: 'El Continuity Vault guarda una copia cifrada de tu historial y de tu estado de entrega, aparte de los relays: si todos los relays pierden tus eventos, puedes recuperarlos desde el vault.',
  sealed: 'Cada archivo se cifra en tu dispositivo con tu llave de archivo, que es distinta de tu nsec. El operador del vault no tiene esa llave: no puede leer el contenido ni saber con quién hablas ni qué eventos guardas.',
  metadata: 'El operador sí ve tu cuenta del vault, cuántos archivos guardas, su tamaño aproximado y cuándo los subes, reemplazas, lees o borras, además de la dirección IP de cada conexión. Si entras con Acceso, también sabe qué usuario de Acceso eres.',
  key: 'La llave de archivo solo viaja dentro de tu backup, cifrada con la contraseña del backup. Si pierdes el backup y este dispositivo, no hay forma de recuperarla: el operador tampoco la tiene.',
  groups: 'Los mensajes de los grupos seguros se guardan ya descifrados, cifrados con tu llave de archivo: quien consiga tu backup, su contraseña y acceso a tu cuenta del vault puede leer ese historial, algo que MLS por sí solo no permite con llaves obtenidas después.',
  deletion: 'Borrar quita del servidor los archivos y sus metadatos en el momento; las copias de seguridad del operador pueden conservar los archivos, cifrados, y sus metadatos hasta que caduquen.',
  retention: 'Cada archivo se guarda hasta que lo borras o hasta que vence su plazo, contado desde la última vez que se guardó: el operador del vault puede fijar un plazo máximo y tú puedes elegir uno más corto. Al vencer, el servidor borra el archivo y sus metadatos.',
  export: 'Puedes exportar el vault en un archivo JSON abierto: tus eventos firmados, que cualquier cliente Nostr puede verificar y publicar, los mensajes de tus grupos seguros y tu estado de entrega. El archivo no va cifrado: los mensajes de grupo quedan en claro, así que guárdalo con cuidado.',
} as const;

/** The version recorded with a managed key's consent: the reviewed copy and the terms that were shown. */
export function managedConsentVersion(termsVersion?: string): string {
  return `textos ${DISCLOSURE_VERSION}; términos ${termsVersion ?? 'no publicados'}`;
}

/** Every statement the panel can show, for review and versioning (not tied to one configuration). */
export function disclosureCatalog(): Disclosure[] {
  const out: Disclosure[] = [];
  for (const [control, options] of Object.entries(CATALOG) as Array<[keyof SovereigntyConfig, Record<string, Entry>]>) {
    for (const [option, entry] of Object.entries(options)) out.push({ control, option, ...entry });
  }
  const base = { ...PRESETS.convenience } as SovereigntyConfig;
  for (const flag of ['remotePreviews', 'deliveryReceipts', 'readReceipts', 'stripFileMetadata'] as const) {
    for (const v of [true, false]) out.push(disclose({ ...base, [flag]: v }).find((x) => x.control === flag)!);
  }
  out.push(disclose({ ...base, quorum: 2 }).find((x) => x.control === 'quorum')!);
  for (const [key, statement] of Object.entries(MANAGED_CONSENT_TEXTS)) out.push({ control: 'custody', option: `managed (consentimiento: ${key})`, statement, improves: [], sacrifices: [], trustAssumptions: [] });
  for (const [key, statement] of Object.entries(CONTINUITY_VAULT_TEXTS)) out.push({ control: 'cloudBackup', option: `continuity-vault (${key})`, statement, improves: [], sacrifices: [], trustAssumptions: [] });
  return out;
}

export function disclose(config: SovereigntyConfig): Disclosure[] {
  const out: Disclosure[] = [];
  for (const [control, options] of Object.entries(CATALOG) as Array<[keyof SovereigntyConfig, Record<string, Entry>]>) {
    const option = String(config[control]);
    const entry = options[option];
    if (entry) out.push({ control, option, ...entry });
  }
  out.push({
    control: 'remotePreviews',
    option: String(config.remotePreviews),
    statement: config.remotePreviews ? 'Las previews remotas se cargan automáticamente: el servidor de origen ve tu IP.' : 'Previews remotas bloqueadas: ningún enlace se carga sin tu acción.',
    improves: config.remotePreviews ? [] : ['privacidad-operador'],
    sacrifices: config.remotePreviews ? ['privacidad-operador'] : [],
    trustAssumptions: [],
  });
  out.push({
    control: 'deliveryReceipts',
    option: String(config.deliveryReceipts),
    statement: config.deliveryReceipts ? 'Confirmaciones de entrega activadas (cifradas con gift wrap): tus contactos saben cuándo recibe tu dispositivo sus mensajes.' : 'Confirmaciones de entrega desactivadas.',
    improves: [],
    sacrifices: config.deliveryReceipts ? ['privacidad-operador'] : [],
    trustAssumptions: [],
  });
  out.push({
    control: 'readReceipts',
    option: String(config.readReceipts),
    statement: config.readReceipts ? 'Confirmaciones de lectura activadas (cifradas): tus contactos sabrán cuándo lees.' : 'Confirmaciones de lectura desactivadas.',
    improves: [],
    sacrifices: config.readReceipts ? ['privacidad-operador'] : [],
    trustAssumptions: [],
  });
  out.push({
    control: 'stripFileMetadata',
    option: String(config.stripFileMetadata),
    statement: config.stripFileMetadata
      ? 'Se quitan los metadatos (EXIF, ubicación, datos del dispositivo) de las imágenes JPEG, PNG y WebP antes de enviarlas; las imágenes que no se pueden limpiar (HEIC, TIFF/RAW) se rechazan. Los demás archivos salen tal cual.'
      : 'Los archivos salen con sus metadatos: una foto puede revelar dónde y con qué dispositivo se tomó.',
    improves: config.stripFileMetadata ? ['privacidad-operador'] : [],
    sacrifices: config.stripFileMetadata ? [] : ['privacidad-operador'],
    trustAssumptions: [],
  });
  out.push({
    control: 'quorum',
    option: String(config.quorum),
    statement: `Un mensaje se considera replicado cuando ${config.quorum} relay(s) lo aceptan. "Aceptado por relay" no significa "recibido" ni "leído".`,
    improves: config.quorum > 1 ? ['recuperabilidad'] : [],
    sacrifices: [],
    trustAssumptions: [],
  });
  return out;
}

export type DimensionSummary = Record<Dimension, { improvedBy: string[]; reducedBy: string[] }>;

/** Per-dimension summary backed by the concrete statements (no simplistic single score, spec §9.1). */
export function summarize(config: SovereigntyConfig): DimensionSummary {
  const dims: Dimension[] = ['soberania', 'privacidad-operador', 'recuperabilidad', 'control-institucional'];
  const res = Object.fromEntries(dims.map((k) => [k, { improvedBy: [] as string[], reducedBy: [] as string[] }])) as DimensionSummary;
  for (const item of disclose(config)) {
    for (const dim of item.improves) res[dim].improvedBy.push(item.statement);
    for (const dim of item.sacrifices) res[dim].reducedBy.push(item.statement);
  }
  return res;
}
