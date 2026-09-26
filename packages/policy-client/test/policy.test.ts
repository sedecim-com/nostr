import { describe, expect, it } from 'vitest';
import { evaluate, type Device, type Resource, type Subject } from '../src/index';

const alice: Subject = { pubkey: 'a', roles: ['analyst'], attributes: { department: 'legal', clearance: 'confidential' } };
const bob: Subject = { pubkey: 'b', roles: ['guest'], attributes: { department: 'sales' } };
const aliceDevice: Device = { id: 'd1', ownerPubkey: 'a', trust: 'registered', registeredAt: 0 };
const channel: Resource = {
  id: 'legal-room',
  kind: 'channel',
  sensitivity: 'confidential',
  rules: [
    { actions: ['read', 'publish'], anyRole: ['analyst', 'admin'], attributes: { department: 'legal' } },
    { actions: ['admin'], anyRole: ['admin'] },
  ],
};

describe('RBAC/ABAC (FR-023, FR-024)', () => {
  it('allows a subject with role, attribute, clearance and a registered device', () => {
    expect(evaluate({ subject: alice, device: aliceDevice, resource: channel, action: 'publish' }).allow).toBe(true);
  });
  it('denies without the required role/attribute or clearance', () => {
    expect(evaluate({ subject: bob, device: { ...aliceDevice, ownerPubkey: 'b' }, resource: channel, action: 'read' }).allow).toBe(false);
    expect(evaluate({ subject: alice, device: aliceDevice, resource: channel, action: 'admin' }).reasons[0]).toMatch(/missing role/);
  });
  it('denies revoked or foreign devices and missing devices on sensitive resources', () => {
    expect(evaluate({ subject: alice, device: { ...aliceDevice, revokedAt: 1 }, resource: channel, action: 'read', now: 2 }).reasons).toEqual(['device revoked']);
    expect(evaluate({ subject: alice, device: { ...aliceDevice, ownerPubkey: 'x' }, resource: channel, action: 'read' }).allow).toBe(false);
    expect(evaluate({ subject: alice, resource: channel, action: 'read' }).allow).toBe(false);
  });
  it('defaults to deny', () => {
    expect(evaluate({ subject: alice, resource: { id: 'x', kind: 'workspace', sensitivity: 'internal', rules: [] }, action: 'read' })).toMatchObject({ allow: false });
  });
});
