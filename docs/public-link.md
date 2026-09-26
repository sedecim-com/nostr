# Vínculo público entre personas como evento Nostr (FR007-04)

Un usuario puede tener varias personas (claves Nostr) separadas. Por defecto **no están vinculadas**
(FR-007). El servicio de identidad permite vínculos privados, selectivos o públicos (FR007-02, FR007-03);
este documento define un paso adicional y **opcional**: publicar un vínculo público como **evento Nostr
firmado por las dos personas**, que cualquiera puede verificar sin confiar en el servicio de identidad, en
un relay ni en quien lo publica.

Implementación: `packages/identity/src/public-link.ts` (`createPublicLink`, `signLinkConsent`,
`finalizePublicLink`, `verifyPublicLink`, `publicLinkDeletion`); pruebas en
`packages/identity/test/public-link.test.ts`.

## Por qué es opcional y viene desactivado

Publicar el vínculo **desanonimiza de forma pública y permanente**: el evento se replica en relays que no
controlas, cualquiera puede guardarlo y demostrar después que ambas claves pertenecen a la misma persona. Una
solicitud de borrado (NIP-09) no retira las copias que ya existen. Por eso:

- Solo se ofrece cuando el vínculo ya es de visibilidad **pública** y es una casilla aparte, **desmarcada por
  defecto**.
- El diálogo de confirmación muestra un aviso destacado y exige marcar "Entiendo que es público y permanente";
  en código, `createPublicLink` exige `confirm: true` y `acknowledgePermanent: true` (si no, lanza
  `ConsentRequiredError`).
- Los perfiles **Soberano** (custodia `offline`) y **Soberano Tor** (red `tor-only`) **lo rechazan**
  (`PublicLinkRefusedError`): contradice la compartimentación que esos perfiles prometen. La web desactiva la
  casilla y explica por qué.
- Si una de las personas usa un perfil pseudónimo, se muestra además el aviso de que vincularla contradice
  ese perfil.

## Formato

Evento **kind 30078** (NIP-78, reemplazable parametrizado: un vínculo por par y autor) publicado por la
persona A:

```json
{
  "kind": 30078,
  "pubkey": "<A>",
  "created_at": 1700000000,
  "content": "acceso-nostr/persona-link/v1\n<pubkey menor>\n<pubkey mayor>\n1700000000",
  "tags": [
    ["d", "acceso-nostr:persona-link:<B>"],
    ["p", "<B>"],
    ["issued", "1700000000"],
    ["alt", "Vínculo público entre dos personas Nostr: ambas claves lo firmaron (…)"],
    ["counter-signature", "<evento de consentimiento de B, JSON>"]
  ],
  "id": "…",
  "sig": "<firma Schnorr de A>"
}
```

- **Declaración canónica** (`content`): la cadena `acceso-nostr/persona-link/v1`, las dos pubkeys en hex
  **ordenadas lexicográficamente** y el instante de emisión (`issued`, segundos Unix), separadas por `\n`.
  Al estar ordenadas, las dos personas firman exactamente el mismo texto.
- **Consentimiento de B** (`counter-signature`): un evento completo firmado por B con la misma estructura
  vista desde su lado (`kind` 30078, `d` = `acceso-nostr:persona-link:<A>`, `p` = A, el mismo `issued` y la
  misma declaración), sin `counter-signature`. Se firma con cualquier signer (local, NIP-07, NIP-46, gestionado)
  porque es un evento Nostr normal: no hace falta firmar bytes arbitrarios.
- **Firma de A**: la firma del evento externo cubre todas las etiquetas, incluido el consentimiento de B, así
  que A no puede cambiar lo que B firmó ni B puede reutilizarse en otro evento sin que A lo firme de nuevo.

Flujo en dos dispositivos: B ejecuta `signLinkConsent(signerB, A, issued)` y entrega el evento a A (por
ejemplo, por mensaje directo); A ejecuta `finalizePublicLink(signerA, consentimiento)` y publica el resultado.
Si las dos personas están en el mismo almacén (la web), `createPublicLink(signerA, signerB, …)` hace ambos
pasos.

## Verificación por terceros

`verifyPublicLink(evento)` acepta el vínculo solo si:

1. El evento externo tiene firma válida, `kind` 30078, exactamente una etiqueta `p` (B ≠ A), `d` =
   `acceso-nostr:persona-link:<B>`, un único `issued` y `content` igual a la declaración canónica de (A, B, issued).
2. Hay **exactamente una** `counter-signature`, es JSON de un evento con firma válida **de B** (la pubkey de
   la etiqueta `p`), y ese evento cumple lo mismo desde el lado de B (`p` = A, `d` = `…:<A>`, mismo `issued`,
   misma declaración).

Se rechazan, entre otros (probados): el vínculo de un solo lado (sin consentimiento), el consentimiento
firmado por otra clave, el consentimiento alterado después de firmarse, el consentimiento para otro instante
o para otra persona, cambios en el evento externo sin volver a firmar, y el `p` cambiado conservando el
consentimiento original.

Para buscar vínculos de una persona: `{"kinds": [30078], "#p": ["<pubkey>"]}` (vínculos donde es B) y
`{"kinds": [30078], "authors": ["<pubkey>"]}` filtrando por el prefijo del `d` (donde es A). Un evento de
kind 30078 con otro `d` no es un vínculo.

## Retirar un vínculo

`publicLinkDeletion(B, A)` genera una solicitud de borrado NIP-09 (kind 5 con la etiqueta
`a` = `30078:<A>:acceso-nostr:persona-link:<B>`). Los relays y los lectores **pueden ignorarla** y las copias
ya descargadas siguen siendo verificables: retirar el vínculo no deshace la desanonimización.
