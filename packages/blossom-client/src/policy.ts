/**
 * FR018-06: what one attachment may weigh. The client checks it before the file is read into memory, sanitized,
 * encrypted and uploaded, and again when a blob is downloaded, because the browser and the CLI hold the whole file in
 * memory at each step. The servers have their own caps (blob-store `BLOB_MAX_BYTES`, Buzz `/media`); these are lower on
 * purpose, so a file the client accepts is one the servers take. docs/attachments.md has the reasons and what the
 * policy does not do (no malware scan).
 */
const MiB = 1024 * 1024;

/** Most bytes of one attachment, by where it goes (1 MB = 1 MiB = 1 048 576 bytes). */
export const MAX_ATTACHMENT_BYTES = {
  /** An attachment of a direct message, encrypted in the client. */
  dm: 25 * MiB,
  /** The media of a secure group (MIP-04), encrypted in the client. */
  group: 25 * MiB,
  /** An image posted in a NIP-29 channel, public to the members of the channel and the operator. */
  channelImage: 10 * MiB,
  /** The avatar of a public profile. */
  avatar: 1_000_000,
} as const;

export type AttachmentFlow = keyof typeof MAX_ATTACHMENT_BYTES;

/**
 * Most a client downloads for one blob: the largest upload plus what encryption adds. A larger file that another
 * client uploaded is not opened here (Buzz accepts images up to 50 MiB in its tests: they are not shown).
 */
export const MAX_DOWNLOAD_BYTES = 26 * MiB;

const WHAT: Record<AttachmentFlow | 'download', string> = {
  dm: 'los adjuntos de mensajes directos',
  group: 'los archivos de los grupos seguros',
  channelImage: 'las imágenes de los canales',
  avatar: 'el avatar del perfil',
  download: 'los archivos que se descargan',
};

const mb = (bytes: number) => `${(bytes / MiB).toFixed(1).replace('.', ',')} MB`;

/** A file over the limit of its flow. `message` is what the user is shown. */
export class AttachmentTooLargeError extends Error {
  constructor(
    readonly flow: AttachmentFlow | 'download',
    /** The size found, when it is known (a download cut off while streaming does not know it). */
    readonly size: number | undefined,
    readonly limit: number,
  ) {
    super(`${size === undefined ? 'El archivo es demasiado grande' : `El archivo pesa ${mb(size)}`} y ${WHAT[flow]} pueden pesar como mucho ${mb(limit)}.`);
    this.name = 'AttachmentTooLargeError';
  }
}

/** Throws AttachmentTooLargeError when `size` (bytes) is over the limit of `flow`. Call it with `File.size` before reading the file. */
export function checkAttachmentSize(flow: AttachmentFlow, size: number): void {
  const limit = MAX_ATTACHMENT_BYTES[flow];
  if (size > limit) throw new AttachmentTooLargeError(flow, size, limit);
}
