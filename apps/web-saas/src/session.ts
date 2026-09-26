import { nip19, nip49, generateSecretKey, npubEncode, selfTestKey, wipe, CUSTODY_FACTS, type Signer } from '@sedecim/nostr-core';
import { RelayPool } from '@sedecim/relay-pool';
import { LocalSigner, Nip07Signer, Nip46Signer, parseBunkerUrl } from '@sedecim/signer';
import { EncryptedStore, LocalStorageBackend, type Collection } from '@sedecim/encrypted-store';
import { DeliveryEngine, type OutboxRecord } from '@sedecim/delivery-engine';

export type CustodyChoice = 'create' | 'import' | 'nip07' | 'nip46' | 'unlock';

export interface WebSession {
  signer: Signer;
  pubkey: string;
  relays: string[];
  pool: RelayPool;
  engine: DeliveryEngine;
  store: EncryptedStore;
  keyStore: Collection<string>;
  custodyLabel: string;
}

/**
 * The SaaS web app is a first-class Nostr client (spec §15): it signs locally or through an external
 * signer and talks WebSocket to the same relays as Buzz Desktop/Mobile. The backend never sees the nsec.
 */
export async function openSession(input: { choice: CustodyChoice; localPass: string; secret: string; ncryptsecPass: string; relays: string[] }): Promise<WebSession> {
  const store = await EncryptedStore.open(new LocalStorageBackend('sedecim-web'), input.localPass, { logN: 15 });
  const keyStore = store.collection<string>('key');
  let signer: Signer;
  let custodyLabel: string;
  const saveLocal = async (sk: Uint8Array) => {
    await keyStore.put('ncryptsec', await nip49.encryptKeyAsync(sk, input.localPass, 16, 0x01));
    signer = new LocalSigner(sk, 'local');
    wipe(sk);
  };
  switch (input.choice) {
    case 'create': {
      const sk = generateSecretKey();
      if (!selfTestKey(sk).ok) throw new Error('self-test de llave falló');
      await saveLocal(sk);
      custodyLabel = 'Llave local (navegador)';
      break;
    }
    case 'import': {
      let sk: Uint8Array;
      if (input.secret.startsWith('ncryptsec')) sk = (await nip49.decryptKeyAsync(input.secret.trim(), input.ncryptsecPass)).secretKey;
      else {
        const d = nip19.decode(input.secret.trim());
        if (d.type !== 'nsec') throw new Error('se esperaba nsec o ncryptsec');
        sk = d.data;
      }
      if (!selfTestKey(sk).ok) throw new Error('la llave importada no pasó el self-test');
      await saveLocal(sk);
      custodyLabel = 'Llave local importada';
      break;
    }
    case 'unlock': {
      const enc = await keyStore.get('ncryptsec');
      if (!enc) throw new Error('no hay llave guardada en este navegador');
      const { secretKey } = await nip49.decryptKeyAsync(enc, input.localPass);
      signer = new LocalSigner(secretKey, 'local');
      wipe(secretKey);
      custodyLabel = 'Llave local (navegador)';
      break;
    }
    case 'nip07':
      signer = new Nip07Signer();
      custodyLabel = 'Signer externo (NIP-07)';
      break;
    case 'nip46': {
      const remote = new Nip46Signer(parseBunkerUrl(input.secret.trim()), { pool: new RelayPool() });
      await remote.connect();
      signer = remote;
      custodyLabel = 'Signer remoto (NIP-46)';
      break;
    }
  }
  const authedPool = new RelayPool({ signer: signer!, authMode: 'on-demand' });
  const engine = new DeliveryEngine({ store: store.collection<OutboxRecord>('outbox'), publisher: authedPool, signer: signer!, retry: { baseMs: 2000, maxMs: 60_000 } });
  void engine.resume();
  return { signer: signer!, pubkey: await signer!.getPublicKey(), relays: input.relays, pool: authedPool, engine, store, keyStore, custodyLabel: custodyLabel! };
}

export function custodyFacts(s: WebSession): string[] {
  const f = CUSTODY_FACTS[s.signer.custody];
  return [
    `Modo de custodia: ${s.custodyLabel}.`,
    f.operatorCanSign ? 'La plataforma tiene capacidad técnica de firmar como tú (CUSTODIAL).' : 'La plataforma NO puede firmar como tú.',
    f.operatorCanRecover ? 'La plataforma puede recuperar tu llave.' : 'La plataforma NO puede recuperar tu llave: guarda un backup.',
  ];
}

export function shortNpub(pubkey: string): string {
  const n = npubEncode(pubkey);
  return `${n.slice(0, 12)}…${n.slice(-4)}`;
}

