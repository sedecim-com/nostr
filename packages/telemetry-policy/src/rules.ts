/*
 * Value rules shared by the traces (NFR007-02) and the crash reports (NFR007-03). Pure functions with no Node
 * built-in, so the web can import them through `@sedecim/telemetry-policy/crash-report`.
 */

/** Shapes of values, not of words: 8+ hex characters in a row, 4+ digits in a row, or a NIP-19 entity. */
export const VALUE_LIKE = /[0-9a-f]{8}|\d{4}|(?:npub|nsec|nprofile|nevent|naddr|note|nrelay|ncryptsec)1/i;

/** A status code, or a class name made of capitalised words without digits (`ReplayStoreFullError`). */
export const isErrorType = (v: string) => /^[1-5]\d\d$/.test(v) || (v.length <= 64 && /^(?:[A-Z][a-z]{1,14})+$/.test(v) && !VALUE_LIKE.test(v));
