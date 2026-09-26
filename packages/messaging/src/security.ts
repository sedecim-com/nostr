/** Conversation types and their real cryptographic properties (spec §10.3, §20.2). */
export type ConversationType = 'workspace-channel' | 'private-dm' | 'high-security-group';

export interface ConversationSecurity {
  technology: string;
  e2ee: boolean;
  forwardSecrecy: boolean;
  postCompromiseSecurity: boolean;
  relaySeesPlaintext: boolean;
  relaySeesParticipants: string;
  notes: string;
}

export const CONVERSATION_SECURITY: Record<ConversationType, ConversationSecurity> = {
  'workspace-channel': {
    technology: 'Buzz / NIP-29',
    e2ee: false,
    forwardSecrecy: false,
    postCompromiseSecurity: false,
    relaySeesPlaintext: true,
    relaySeesParticipants: 'sí (miembros, autor, grupo)',
    notes: 'Colaboración estándar; buscable según política. No etiquetar como E2EE.',
  },
  'private-dm': {
    technology: 'NIP-17 + NIP-44 + NIP-59',
    e2ee: true,
    forwardSecrecy: false,
    postCompromiseSecurity: false,
    relaySeesPlaintext: false,
    relaySeesParticipants: 'destinatario (tag p) sí; remitente oculto por gift wrap',
    notes: 'Sin forward secrecy ni PCS: el compromiso de la nsec expone el historial. No es la opción por defecto para high-risk.',
  },
  'high-security-group': {
    technology: 'Marmot + MLS (RFC 9420)',
    e2ee: true,
    forwardSecrecy: true,
    postCompromiseSecurity: true,
    relaySeesPlaintext: false,
    relaySeesParticipants: 'minimizado (depende de la implementación Marmot)',
    notes: 'Requiere proveedor Marmot configurado y conformance tests contra la versión fijada.',
  },
};
