import type { CloudBackupOption, MessageExpirationOption } from './types';

/**
 * PANEL-06 (§12.2): the expiration of direct messages (NIP-40) and the deletion of one's own, with what each does and
 * does not do. Three levels, the most specific winning: the profile's default (every preset says `off`), the persona's
 * own choice (its panel configuration) and a conversation's (a DM with one contact). A choice only applies to the
 * messages sent after it: a message keeps the expiration it was sent with.
 */
export const MESSAGE_EXPIRATION_OPTIONS = ['off', '1d', '7d', '30d', '90d'] as const satisfies readonly MessageExpirationOption[];

const DAYS: Record<MessageExpirationOption, number | undefined> = { off: undefined, '1d': 1, '7d': 7, '30d': 30, '90d': 90 };

/** Spanish label of each option, for the web and the CLI. */
export const MESSAGE_EXPIRATION_LABELS: Record<MessageExpirationOption, string> = { off: 'sin caducidad', '1d': '1 día', '7d': '7 días', '30d': '30 días', '90d': '90 días' };

export function isMessageExpirationOption(v: unknown): v is MessageExpirationOption {
  return typeof v === 'string' && (MESSAGE_EXPIRATION_OPTIONS as readonly string[]).includes(v);
}

/** The days an option asks a message to be kept; undefined for `off`. */
export function expirationDays(option: MessageExpirationOption): number | undefined {
  return DAYS[option];
}

export type ExpirationSource = 'conversation' | 'persona' | 'profile';

/** What each level says; undefined (or anything that is not an option) means «as the level below». */
export interface ExpirationLevels {
  profile?: MessageExpirationOption;
  persona?: MessageExpirationOption;
  conversation?: MessageExpirationOption;
}

/**
 * The expiration of the next message of a conversation: the conversation's choice, else the persona's, else the
 * profile's default, else none. `off` is a choice too: a conversation set to `off` has no expiration whatever the
 * persona says.
 */
export function resolveMessageExpiration(levels: ExpirationLevels): { option: MessageExpirationOption; source: ExpirationSource } {
  if (isMessageExpirationOption(levels.conversation)) return { option: levels.conversation, source: 'conversation' };
  if (isMessageExpirationOption(levels.persona)) return { option: levels.persona, source: 'persona' };
  return { option: isMessageExpirationOption(levels.profile) ? levels.profile : 'off', source: 'profile' };
}

/**
 * PANEL-06: what the expiration of direct messages does and does not do, shown where it is chosen (the panel, the
 * conversation, `persona expiration` and `dm expiration` in the CLI). Part of the reviewed copy (disclosureCatalog,
 * docs/disclosures.md).
 */
export const MESSAGE_EXPIRATION_TEXTS = {
  request:
    'La caducidad es una petición (NIP-40): los relays que la respetan dejan de servir el mensaje al caducar, aunque pueden seguir guardándolo, y los que no la respetan lo siguen sirviendo. El cliente de tu contacto puede no respetarla, y tu contacto pudo guardar el mensaje o hacer una captura antes.',
  relay:
    'Cada mensaje cifrado lleva a la vista su fecha de caducidad, redondeada hacia arriba a la medianoche (UTC): el relay la ve, no el contenido. Los mensajes con el mismo plazo enviados el mismo día (UTC) llevan la misma fecha, y un mensaje puede durar hasta un día más de lo elegido.',
  local:
    'Al caducar, este cliente deja de mostrar el mensaje y borra lo que guarda de él: el mensaje enviado, su entrega (outbox) y las copias del Continuity Vault que conoce, si llega al vault. No espera a tu contacto; si el dispositivo está apagado, lo hace al volver a abrir la persona.',
  past: 'Cambiar la caducidad solo afecta a los mensajes nuevos: los ya enviados conservan la que tenían, o ninguna si no la tenían.',
  vault:
    'Las copias del Continuity Vault no caducan con el mensaje: este cliente borra las que conoce cuando caduca o lo borras, y la siguiente copia del historial ya no lo incluye. Las demás vencen con el plazo del vault, y las copias de seguridad de su operador, con la retención de esas copias.',
} as const;

/**
 * PANEL-06: what deleting one of the persona's own direct messages does and does not do, shown before it is confirmed
 * (the web's dialog; `dm delete` without --yes in the CLI). Part of the reviewed copy (disclosureCatalog,
 * docs/disclosures.md). `copies` opens with the same notice as deleting in a channel (CHANNEL_DELETION_TEXTS.copies).
 */
export const DM_DELETION_TEXTS = {
  request:
    'Borrar un mensaje tuyo envía una petición de borrado, cifrada como un mensaje más (NIP-17), a cada destinatario y a tus otros dispositivos. Solo puedes borrar los mensajes que escribiste tú.',
  local: 'Este dispositivo lo quita en el momento de la conversación, del mensaje enviado y de su entrega (outbox), y borra las copias del Continuity Vault que conoce: ahora o, si el vault no responde, más adelante.',
  copies:
    'Borrar no retira las copias que ya circularon: las copias replicadas pueden seguir existiendo. Los relays guardan el mensaje cifrado, el cliente de tu contacto puede no aplicar la petición, y tu contacto pudo guardarlo o hacer una captura antes.',
} as const;

/**
 * PANEL-06: when the persona's Continuity Vault may keep copies of expiring messages longer than they ask to live, in
 * the user's words; undefined when it may not. The vault is in use with the cloud backup on and a vault in the
 * deployment. `retentionDays` is the account's VAULT-05 `effective_days` (null: until deleted), undefined when unknown.
 */
export function vaultExpirationNotice(option: MessageExpirationOption, ctx: { cloudBackup: CloudBackupOption; continuityVault?: boolean; retentionDays?: number | null }): string | undefined {
  const days = expirationDays(option);
  if (days === undefined || ctx.cloudBackup === 'off' || ctx.continuityVault === false) return undefined;
  const kept = ctx.retentionDays;
  if (typeof kept === 'number' && kept <= days) return undefined;
  const asks = `Los mensajes piden caducar a los ${MESSAGE_EXPIRATION_LABELS[option]}`;
  const bound = 'Un plazo más corto en el vault lo acota, pero se aplica a todo lo que guarda.';
  if (kept === undefined)
    return `${asks}, pero el Continuity Vault guarda sus copias con su propio plazo, que desde aquí no se conoce (lo muestra la tarjeta del vault): las que este dispositivo no llegue a borrar siguen allí, cifradas, hasta que venza.`;
  if (kept === null) return `${asks}, pero tu vault guarda cada archivo hasta que lo borres: las copias que este dispositivo no llegue a borrar (por ejemplo, porque no vuelve a abrirse) siguen allí, cifradas. ${bound}`;
  return `${asks}, pero tu vault guarda cada archivo ${kept} días desde que se guardó: las copias que este dispositivo no llegue a borrar pueden seguir allí, cifradas, hasta entonces. ${bound}`;
}
