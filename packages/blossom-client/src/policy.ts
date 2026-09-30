/**
 * FR018-06: what one attachment may weigh. The client checks it before the file is read into memory, sanitized,
 * encrypted and uploaded, and again when a blob is downloaded, because the browser and the CLI hold the whole file in
 * memory at each step. The servers have their own caps (blob-store `BLOB_MAX_BYTES`, Buzz `/media`); these are lower on
 * purpose, so a file the client accepts is one the servers take. docs/attachments.md has the reasons and what the
 * policy does not do (no malware scan).
 */
/** Sizes here are decimal, as the user sees them: 1 MB = 1 000 000 bytes. */
const MB = 1_000_000;

/** Most bytes of one attachment, by where it goes. */
export const MAX_ATTACHMENT_BYTES = {
  /** An attachment of a direct message, encrypted in the client. */
  dm: 25 * MB,
  /** The media of a secure group (MIP-04), encrypted in the client. */
  group: 25 * MB,
  /** An image posted in a NIP-29 channel, public to the members of the channel and the operator. */
  channelImage: 10 * MB,
  /** The avatar of a public profile. */
  avatar: 1 * MB,
} as const;

export type AttachmentFlow = keyof typeof MAX_ATTACHMENT_BYTES;

/**
 * Most a client downloads for one blob: the largest upload plus what encryption adds. A larger file that another
 * client uploaded is not opened here (Buzz accepts images up to 50 MiB in its tests: they are not shown).
 */
export const MAX_DOWNLOAD_BYTES = 26 * MB;

const WHAT: Record<AttachmentFlow | 'download', string> = {
  dm: 'los adjuntos de mensajes directos',
  group: 'los archivos de los grupos seguros',
  channelImage: 'las imágenes de los canales',
  avatar: 'los avatares de los perfiles',
  download: 'los archivos que se descargan',
};

const fmt = (tenths: number) => `${(tenths / 10).toFixed(1).replace('.', ',')} MB`;
/** The limit as it is, and the size of the file rounded up: a file over the limit never reads as equal to it. */
const limitMb = (bytes: number) => fmt(Math.round(bytes / (MB / 10)));
const sizeMb = (bytes: number) => fmt(Math.ceil(bytes / (MB / 10)));

/** A file over the limit of its flow. `message` is what the user is shown. */
export class AttachmentTooLargeError extends Error {
  constructor(
    readonly flow: AttachmentFlow | 'download',
    /** The size found, when it is known (a download cut off while streaming does not know it). */
    readonly size: number | undefined,
    readonly limit: number,
  ) {
    super(`${size === undefined ? 'El archivo es demasiado grande' : `El archivo pesa ${sizeMb(size)}`} y ${WHAT[flow]} pueden pesar como mucho ${limitMb(limit)}.`);
    this.name = 'AttachmentTooLargeError';
  }
}

/** Throws AttachmentTooLargeError when `size` (bytes) is over the limit of `flow`. Call it with `File.size` before reading the file. */
export function checkAttachmentSize(flow: AttachmentFlow, size: number): void {
  const limit = MAX_ATTACHMENT_BYTES[flow];
  if (size > limit) throw new AttachmentTooLargeError(flow, size, limit);
}
