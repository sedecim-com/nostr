import type { StorageBackend } from './backends';

/** Browser backend over localStorage (base64 values). Suitable for small datasets only. */
export class LocalStorageBackend implements StorageBackend {
  constructor(private readonly ns = 'sedecim', private readonly storage: Storage = globalThis.localStorage) {}
  private k(key: string) {
    return `${this.ns}/${key}`;
  }
  async get(key: string) {
    const v = this.storage.getItem(this.k(key));
    return v === null ? undefined : Uint8Array.from(atob(v), (c) => c.charCodeAt(0));
  }
  async put(key: string, value: Uint8Array) {
    let s = '';
    for (const b of value) s += String.fromCharCode(b);
    this.storage.setItem(this.k(key), btoa(s));
  }
  async delete(key: string) {
    this.storage.removeItem(this.k(key));
  }
  async keys(prefix: string) {
    const out: string[] = [];
    const full = this.k(prefix);
    for (let i = 0; i < this.storage.length; i++) {
      const k = this.storage.key(i);
      if (k?.startsWith(full)) out.push(k.slice(this.ns.length + 1));
    }
    return out;
  }
}
