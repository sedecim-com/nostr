import { createContext, useContext } from 'react';
import type { DeploymentFlags } from '@sedecim/messaging';
import type { SovereigntyConfig } from '@sedecim/profiles';
import type { AccesoUser } from './acceso';
import type { DeploymentConfig } from './config';
import type { ManagedEnv, PersonaSession } from './session';
import type { PersonaBook, PersonaRecord } from './vault';

export interface Workspace {
  cfg: DeploymentConfig;
  flags: DeploymentFlags | undefined;
  book: PersonaBook;
  user: AccesoUser | undefined;
  personas: PersonaRecord[];
  session: PersonaSession | undefined;
  /** The active persona's panel configuration: it drives behaviour, not just display (PANEL-02). */
  config: SovereigntyConfig | undefined;
  selectPersona(id: string): Promise<void>;
  reloadPersonas(): Promise<void>;
  /** Persist the active persona's configuration in the vault (PANEL-03). */
  saveConfig(c: SovereigntyConfig): Promise<void>;
  /** The active persona's record changed in the vault (e.g. its archive key, VAULT-02): refresh the open session. */
  updatePersona(p: PersonaRecord): Promise<void>;
  /** Onboarding: publish the active persona's DM relay list (kind 10050). */
  publishDmRelays(): Promise<void>;
  /** How managed personas reach the managed-signer (SaaS with an Acceso session only). */
  managedEnv: ManagedEnv;
  notify(message: string, severity?: 'success' | 'info' | 'warning' | 'error'): void;
}

export const WorkspaceContext = createContext<Workspace | undefined>(undefined);

export function useWorkspace(): Workspace {
  const w = useContext(WorkspaceContext);
  if (!w) throw new Error('useWorkspace outside provider');
  return w;
}

/** Relays the active configuration allows: Tor-only cannot be honoured from a browser (spec §14). */
export function sendBlockedReason(config: SovereigntyConfig | undefined): string | undefined {
  if (!config) return 'Sin persona activa';
  if (config.network === 'tor-only') return 'Tor-only no puede garantizarse desde un navegador: usa el cliente soberano.';
  return undefined;
}
