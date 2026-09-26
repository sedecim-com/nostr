import type { Dimension, Disclosure, SovereigntyConfig } from './types';

type Entry = Omit<Disclosure, 'control' | 'option'>;
const d = (statement: string, improves: Dimension[], sacrifices: Dimension[], trustAssumptions: string[] = []): Entry => ({ statement, improves, sacrifices, trustAssumptions });

const CATALOG: { [K in keyof SovereigntyConfig]?: Record<string, Entry> } = {
  custody: {
    local: d('La llave se genera y guarda cifrada en este dispositivo. La plataforma no puede firmar ni recuperar tu llave.', ['soberania', 'privacidad-operador'], ['recuperabilidad'], ['Seguridad del dispositivo y de tu passphrase.']),
    offline: d('La llave vive fuera de línea (air-gapped/hardware). Nadie más puede firmar; la recuperación es tu responsabilidad.', ['soberania', 'privacidad-operador'], ['recuperabilidad'], ['Custodia física del respaldo.']),
    external: d('Un signer externo (NIP-46/NIP-07) firma por ti; este cliente nunca ve la nsec.', ['soberania', 'privacidad-operador'], [], ['El signer externo y los permisos que le concedas.']),
    'encrypted-backup': d('El operador almacena un backup cifrado con una clave que solo tú controlas: guarda ciphertext, no la clave de descifrado.', ['recuperabilidad'], [], ['Fortaleza de tu contraseña de backup (scrypt).']),
    managed: d('Managed Key activado: la plataforma tiene capacidad técnica de firmar como tú. Este modo es CUSTODIAL.', ['recuperabilidad', 'control-institucional'], ['soberania', 'privacidad-operador'], ['Operador, su vault (Secrets Manager/KMS) y su personal.']),
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
    marmot: d('Grupos Marmot/MLS: forward secrecy y post-compromise security, con menor compatibilidad con clientes Nostr genéricos.', ['privacidad-operador'], [], ['Implementación Marmot fijada y auditada.']),
  },
  files: {
    'relay-plain': d('Archivos sin cifrar en Blossom: el operador del almacenamiento puede ver el contenido.', [], ['privacidad-operador'], ['Operador del servidor Blossom.']),
    'client-encrypted': d('Archivos cifrados antes de subir: el servidor Blossom solo ve un blob cifrado y su hash.', ['privacidad-operador'], [], []),
  },
  telemetry: {
    standard: d('Telemetría estándar (sin nsec ni contenido E2EE): útil para diagnóstico, revela patrones de uso al operador.', [], ['privacidad-operador'], ['Operador y su stack de observabilidad.']),
    minimal: d('Telemetría mínima: solo salud agregada, sin identificadores de usuario.', [], [], ['Operador.']),
    none: d('Sin telemetría: no se emite ninguna llamada de analytics ni crash reporting.', ['privacidad-operador'], [], []),
  },
  notifications: {
    push: d('Push convencional: Apple/Google y el gateway de push ven cuándo recibes mensajes.', [], ['privacidad-operador'], ['APNs/FCM y gateway de push.']),
    'privacy-push': d('Push con contenido opaco: los servicios push ven que hubo actividad, no el contenido ni el remitente.', [], [], ['APNs/FCM (metadatos de tiempo).']),
    none: d('Sin notificaciones push: nada se revela a servicios push; debes abrir la app para ver mensajes.', ['privacidad-operador'], [], []),
  },
  cloudBackup: {
    off: d('Sin backup en la nube.', ['privacidad-operador'], ['recuperabilidad'], []),
    'ciphertext-user-key': d('Backup en la nube cifrado con clave del usuario: el operador almacena ciphertext pero no la clave de descifrado.', ['recuperabilidad'], [], ['Tu contraseña de backup.']),
    'operator-managed': d('Backup gestionado por el operador: el operador puede restaurar (y por tanto acceder a) los datos.', ['recuperabilidad', 'control-institucional'], ['privacidad-operador', 'soberania'], ['Operador.']),
  },
  localProtection: {
    passphrase: d('El almacén local se abre con tu contraseña (scrypt): sin ella, nadie con acceso a este dispositivo puede leer tus llaves.', ['soberania', 'privacidad-operador'], ['recuperabilidad'], ['Fortaleza de tu contraseña local.']),
    device: d('Desbloqueo sin contraseña con una llave del dispositivo (WebCrypto, no exportable): cualquiera con acceso a este perfil del navegador puede abrir tus llaves.', [], ['soberania', 'privacidad-operador'], ['Seguridad física y de la sesión de este dispositivo.']),
  },
  crashReports: {
    off: d('Crash reporting deshabilitado.', ['privacidad-operador'], [], []),
    'manual-export': d('Los informes de fallo quedan en local y solo salen si los exportas manualmente.', ['privacidad-operador'], [], []),
    'opt-in': d('Informes de fallo opt-in con limpieza de datos sensibles.', [], ['privacidad-operador'], ['Operador.']),
  },
};

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
