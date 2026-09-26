import { createTestCognito } from '@sedecim/service-kit';

const pool = createTestCognito();
export const cfg = pool.cfg;
export const iss = pool.issuer;
export const jwksFetch = pool.jwksFetch;
export const verifier = pool.verifier;
export const token = pool.token;
