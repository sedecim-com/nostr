#!/usr/bin/env node
// NFR010-04: no devDependency in the runtime of an image. Reads the CycloneDX SBOM syft made of the image
// (scripts/image-sbom.sh) and looks up every npm package installed under the app directory in package-lock.json,
// by its path: the entry must exist and must not be dev-only ("dev": true). Packages of the base image (the npm
// that ships with Node, under /usr/local) and the package.json files of subpath exports are not ours to check.
//   node scripts/image-sbom-check.mjs sbom.cdx.json [--app /app] [--lock package-lock.json]
import { readFileSync } from 'node:fs';

const INSTALLED = /^(?:.*\/)?node_modules\/(?:@[^/]+\/)?[^/@][^/]*$/;

/** The npm packages the SBOM found installed under `app`, as their package-lock.json paths. */
export function installedPackages(sbom, app = '/app') {
  const prefix = `${app.replace(/\/$/, '')}/`;
  const out = new Map();
  for (const c of sbom.components ?? []) {
    if (!c.purl?.startsWith('pkg:npm/')) continue;
    const at = (c.properties ?? []).find((p) => p.name === 'syft:location:0:path')?.value ?? '';
    if (!at.startsWith(prefix) || !at.endsWith('/package.json')) continue;
    const lockPath = at.slice(prefix.length, -'/package.json'.length);
    if (INSTALLED.test(lockPath)) out.set(lockPath, `${c.name}@${c.version}`);
  }
  return out;
}

/** What is wrong with the image: dev-only packages, and packages the lock does not know at that path. */
export function checkImage(sbom, lock, app = '/app') {
  const problems = [];
  const packages = installedPackages(sbom, app);
  for (const [path, pkg] of packages) {
    const entry = lock.packages?.[path];
    if (!entry) problems.push(`${pkg} en ${app}/${path} no está en package-lock.json`);
    else if (entry.dev) problems.push(`${pkg} en ${app}/${path} es solo de desarrollo (devDependency)`);
  }
  return { problems, checked: packages.size };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const args = process.argv.slice(2);
  const opt = (name, fallback) => (args.includes(name) ? args[args.indexOf(name) + 1] : fallback);
  const file = args.find((a, i) => !a.startsWith('--') && !['--app', '--lock'].includes(args[i - 1]));
  if (!file) {
    console.error('uso: node scripts/image-sbom-check.mjs sbom.cdx.json [--app /app] [--lock package-lock.json]');
    process.exit(2);
  }
  const app = opt('--app', '/app');
  const { problems, checked } = checkImage(JSON.parse(readFileSync(file, 'utf8')), JSON.parse(readFileSync(opt('--lock', 'package-lock.json'), 'utf8')), app);
  if (problems.length) {
    console.error(`${file}: ${problems.length} paquetes que no deberían ir en la imagen (NFR010-04):\n${problems.join('\n')}`);
    process.exit(1);
  }
  console.log(`${file}: ${checked} paquetes npm en ${app}, ninguno de desarrollo`);
}
