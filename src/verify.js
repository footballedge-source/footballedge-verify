/* global AbortSignal */
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, join, resolve } from 'node:path';
import { URL } from 'node:url';
import { describeEntry, readManifest } from './manifest.js';
import { parseOts } from './ots.js';
import { defaultSystem } from './system.js';
import { parseTimeStampResponse } from './tsr.js';

export const VERSION = '0.1.0';
export const DEFAULT_API = 'https://api.footballedge.io';
export const DEFAULT_SITE = 'https://footballedge.io';

/** FreeTSA's public certificates (https://freetsa.org/index_en.php). */
export const FREETSA_CA_URL = 'https://freetsa.org/files/cacert.pem';
export const FREETSA_TSA_URL = 'https://freetsa.org/files/tsa.crt';
/** SHA-256 of FreeTSA's root certificate (valid until 2041), printed so you can compare it with freetsa.org. */
export const FREETSA_ROOT_SHA256 =
  'a6379e7cecc05faa3cbf076013d745e327bbbaa38c0b9af22469d4701d18aabc';

export const EXPLORERS = ['https://mempool.space/api', 'https://blockstream.info/api'];

export const TSA = /** @type {const} */ ({ freetsa: 'FreeTSA', digicert: 'DigiCert' });

const ID = /^[0-9a-f]{24}$/i;
const SHA = /^[0-9a-f]{64}$/i;

/**
 * What the reader typed: a batch id, a fingerprint, a link to a batch, or a
 * batch file on disk.
 *
 * @returns {{ kind: 'id' | 'sha256' | 'file', value: string }}
 */
export function parseTarget(input, exists = existsSync) {
  const text = String(input ?? '').trim();
  if (!text)
    throw new UsageError('Give a batch id, a fingerprint, a link to a batch or a batch file.');
  if (ID.test(text)) return { kind: 'id', value: text.toLowerCase() };
  if (SHA.test(text)) return { kind: 'sha256', value: text.toLowerCase() };
  if (/^https?:\/\//i.test(text)) {
    const id = /\/(?:results\/proof|proofs)\/([0-9a-f]{24})(?:[/?#]|$)/i.exec(text)?.[1];
    if (id) return { kind: 'id', value: id.toLowerCase() };
    const sha = /\/proofs\/sha256\/([0-9a-f]{64})(?:[/?#]|$)/i.exec(text)?.[1];
    if (sha) return { kind: 'sha256', value: sha.toLowerCase() };
    throw new UsageError(`No batch id in ${text}`);
  }
  if (exists(text)) return { kind: 'file', value: resolve(text) };
  throw new UsageError(
    `${text} is not a batch id (24 hex characters), a fingerprint (64), a link or an existing file.`,
  );
}

export class UsageError extends Error {}

export function sha256Hex(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function utc(date) {
  return `${new Date(date).toISOString().replace('T', ' ').slice(0, 19)} UTC`;
}

/** `5 min 30 s` */
export function duration(ms) {
  const s = Math.round(Math.abs(ms) / 1000);
  if (s < 60) return `${s} s`;
  const m = Math.floor(s / 60);
  if (m < 120) return s % 60 ? `${m} min ${s % 60} s` : `${m} min`;
  const h = Math.floor(m / 60);
  return m % 60 ? `${h} h ${m % 60} min` : `${h} h`;
}

/**
 * Runs every check it can and returns the report; never throws for a failed
 * check (only for bad usage).
 *
 * @param {string} target
 * @param {{
 *   api?: string, site?: string, offline?: boolean, dir?: string,
 *   sha256?: string, ots?: string, freetsaTsr?: string, digicertTsr?: string,
 *   freetsaCa?: string, freetsaCert?: string, caBundle?: string,
 *   openssl?: boolean, otsClient?: boolean,
 * }} [options]
 * @param {Partial<typeof defaultSystem>} [system]
 */
export async function verify(target, options = {}, system = {}) {
  const sys = { ...defaultSystem, ...system };
  const api = (options.api ?? DEFAULT_API).replace(/\/+$/, '');
  const site = (options.site ?? DEFAULT_SITE).replace(/\/+$/, '');
  const offline = options.offline === true;
  const parsed = typeof target === 'object' && target ? target : parseTarget(target);

  const checks = [];
  const add = (status, name, detail) => checks.push({ status, name, detail });
  const report = {
    tool: `footballedge-verify ${VERSION}`,
    target: parsed,
    batch: null,
    kickoff: null,
    file: null,
    sha256: null,
    checks,
    entries: [],
    links: {},
    verdict: 'INCOMPLETE',
    summary: '',
    workdir: null,
  };

  const userAgent = {
    'User-Agent': `footballedge-verify/${VERSION} (+https://footballedge.io/en/results/proof/verify)`,
  };
  const get = async (url) => {
    const res = await sys.fetch(url, { headers: userAgent, signal: AbortSignal.timeout(30_000) });
    return { status: res.status, ok: res.ok, bytes: Buffer.from(await res.arrayBuffer()) };
  };

  // --- 1. the batch file and its record -----------------------------------
  let manifestBytes = null;
  let manifestPath = null;
  if (parsed.kind === 'file') {
    manifestPath = parsed.value;
    manifestBytes = await readFile(manifestPath);
    report.file = { name: basename(manifestPath), bytes: manifestBytes.length, path: manifestPath };
  }

  let record = null;
  if (!offline) {
    const lookup =
      parsed.kind === 'id'
        ? `${api}/proofs/${parsed.value}`
        : `${api}/proofs/sha256/${parsed.kind === 'sha256' ? parsed.value : sha256Hex(manifestBytes)}`;
    try {
      const res = await get(lookup);
      if (res.ok) record = JSON.parse(res.bytes.toString('utf8'));
      else if (res.status === 404)
        add(
          'fail',
          'Published record',
          parsed.kind === 'file'
            ? "No sealed batch has this file's fingerprint. The file is not a FootballEdge batch, or it was changed."
            : 'No sealed batch with this id or fingerprint.',
        );
      else add('skip', 'Published record', `The API answered HTTP ${res.status}; try again later.`);
    } catch (err) {
      add('skip', 'Published record', `Could not reach ${api} (${err.message}).`);
    }
  }
  if (record) {
    report.batch = record.id;
    report.kickoff = record.kickoff;
    report.links.batch = `${site}/en/results/proof/${record.id}`;
    report.links.record = `${site}/en/results`;
  }

  const workdir = options.dir
    ? resolve(options.dir)
    : await mkdtemp(join(tmpdir(), 'footballedge-verify-'));
  if (options.dir) await mkdir(workdir, { recursive: true });
  report.workdir = workdir;
  const keepWorkdir = Boolean(options.dir);

  try {
    if (!manifestBytes && record) {
      try {
        const res = await get(`${api}${record.files.manifest}`);
        if (res.ok) {
          manifestBytes = res.bytes;
          manifestPath = join(workdir, record.files.manifestName);
          await writeFile(manifestPath, manifestBytes);
          report.file = {
            name: record.files.manifestName,
            bytes: manifestBytes.length,
            path: manifestPath,
          };
        } else if (res.status === 403) {
          add(
            'skip',
            'Batch file',
            'Not published yet: a batch file is published once its matches are over. Its fingerprint and timestamps are checked below; run this again after full time to check the file itself.',
          );
        } else add('skip', 'Batch file', `Download failed (HTTP ${res.status}).`);
      } catch (err) {
        add('skip', 'Batch file', `Download failed (${err.message}).`);
      }
    }

    // --- 2. fingerprint and content -----------------------------------------
    const computed = manifestBytes ? sha256Hex(manifestBytes) : null;
    const expected = (record?.sha256 ?? options.sha256 ?? null)?.toLowerCase() ?? null;
    report.sha256 = computed ?? expected;
    if (computed && expected) {
      if (computed === expected)
        add(
          'pass',
          'Fingerprint',
          `SHA-256 of the file is ${computed}, the published fingerprint.`,
        );
      else
        add(
          'fail',
          'Fingerprint',
          `SHA-256 of the file is ${computed}, but the published fingerprint is ${expected}. The file was changed.`,
        );
    } else if (computed) {
      add(
        'info',
        'Fingerprint',
        `SHA-256 of the file is ${computed} (no published fingerprint to compare with offline; pass --sha256).`,
      );
    }

    let manifest = null;
    if (manifestBytes) {
      const read = readManifest(manifestBytes);
      if (!read.ok) add('fail', 'Batch file', read.error);
      else {
        manifest = read.manifest;
        const picks = manifest.entries.filter((e) => e.call === 'pick').length;
        const detail = `${manifest.entries.length} calls (${picks} picks, ${manifest.entries.length - picks} no pick), kick-off ${utc(manifest.kickoff)}${manifest.supersedes ? `, replaces batch ${manifest.supersedes}` : ''}.`;
        if (record && Date.parse(record.kickoff) !== Date.parse(manifest.kickoff))
          add(
            'fail',
            'Batch file',
            `The file says kick-off ${utc(manifest.kickoff)}, the record says ${utc(record.kickoff)}.`,
          );
        else if (read.canonical)
          add('pass', 'Batch file', `Canonical ${manifest.format}: ${detail}`);
        else
          add(
            'warn',
            'Batch file',
            `Readable but not in canonical form (was it re-saved by an editor?): ${detail}`,
          );
        report.kickoff = report.kickoff ?? manifest.kickoff;
        report.entries = manifest.entries.map((e) => ({
          ...describeEntry(e),
          url: `${site}/en/matches/${e.match}`,
        }));
      }
    }

    // The receipts must name this fingerprint: the file's if we have it, else the published one.
    const subject = computed ?? expected;
    const kickoff = report.kickoff ? new Date(report.kickoff) : null;

    // --- 3. receipts on disk --------------------------------------------------
    const receipt = async (name, explicit, sibling, remote) => {
      if (explicit) return resolve(explicit);
      if (parsed.kind === 'file' && existsSync(`${parsed.value}${sibling}`))
        return `${parsed.value}${sibling}`;
      if (!record || !remote) return null;
      const res = await get(`${api}${remote}`).catch(() => null);
      if (!res?.ok) return null;
      const path = join(workdir, `${record.files.manifestName}${sibling}`);
      await writeFile(path, res.bytes);
      return path;
    };

    const opensslPath = options.openssl === false ? null : sys.which('openssl');

    for (const provider of /** @type {const} */ (['freetsa', 'digicert'])) {
      const label = TSA[provider];
      const path = await receipt(
        provider,
        provider === 'freetsa' ? options.freetsaTsr : options.digicertTsr,
        `.${provider}.tsr`,
        record?.files?.tsr?.[provider],
      );
      if (!path) {
        add('skip', `${label} timestamp`, 'No receipt from this authority for this batch.');
        continue;
      }
      let token;
      try {
        token = parseTimeStampResponse(await readFile(path));
      } catch (err) {
        add('fail', `${label} timestamp`, `The .tsr file is unreadable (${err.message}).`);
        continue;
      }
      if (!token.granted) {
        add(
          'fail',
          `${label} timestamp`,
          `The authority refused the request (status ${token.status}).`,
        );
        continue;
      }
      if (!subject) {
        add('info', `${label} timestamp`, `Signed ${token.digestHex} at ${utc(token.genTime)}.`);
      } else if (token.hashAlgorithm !== 'sha256' || token.digestHex !== subject) {
        add(
          'fail',
          `${label} timestamp`,
          `The token is for a different fingerprint (${token.digestHex}).`,
        );
        continue;
      } else if (kickoff && token.genTime.getTime() >= kickoff.getTime()) {
        add(
          'fail',
          `${label} timestamp`,
          `Signed at ${utc(token.genTime)}, ${duration(token.genTime - kickoff)} after kick-off.`,
        );
      } else {
        add(
          'pass',
          `${label} timestamp`,
          `Signs this fingerprint at ${utc(token.genTime)}${kickoff ? `, ${duration(kickoff - token.genTime)} before kick-off` : ''}.`,
        );
      }

      // The signature itself: openssl and the authority's certificates.
      if (options.openssl === false) continue;
      if (!opensslPath) {
        add(
          'skip',
          `${label} signature`,
          `openssl not found. Install OpenSSL, then run: ${opensslHint(provider, manifestPath, path)}`,
        );
        continue;
      }
      const certs = await authorityCerts(provider);
      if (!certs) continue;
      const args = [
        'ts',
        '-verify',
        '-in',
        path,
        ...(manifestPath ? ['-data', manifestPath] : ['-digest', subject]),
        '-CAfile',
        certs.ca,
      ];
      if (certs.untrusted) args.push('-untrusted', certs.untrusted);
      const out = await sys.run(opensslPath, args);
      if (out.code === 0 && /Verification: OK/.test(out.stdout))
        add('pass', `${label} signature`, `openssl ts -verify: OK (${certs.note}).`);
      else
        add(
          'fail',
          `${label} signature`,
          `openssl ts -verify failed: ${lastLine(out.stdout + out.stderr) || `exit code ${out.code}`}`,
        );
    }

    async function authorityCerts(provider) {
      if (provider === 'digicert') {
        const ca = options.caBundle ?? sys.findCaBundle();
        if (!ca) {
          add(
            'skip',
            'DigiCert signature',
            'No trusted root certificate bundle found; pass --ca-bundle <file>.',
          );
          return null;
        }
        return { ca, note: `trusted roots from ${ca}` };
      }
      let ca = options.freetsaCa ?? null;
      let untrusted = options.freetsaCert ?? null;
      if ((!ca || !untrusted) && offline) {
        add(
          'skip',
          'FreeTSA signature',
          'Offline: pass --freetsa-ca cacert.pem --freetsa-cert tsa.crt (from freetsa.org/files).',
        );
        return null;
      }
      try {
        if (!ca) {
          const res = await get(FREETSA_CA_URL);
          if (!res.ok) throw new Error(`HTTP ${res.status}`);
          ca = join(workdir, 'freetsa-cacert.pem');
          await writeFile(ca, res.bytes);
        }
        if (!untrusted) {
          const res = await get(FREETSA_TSA_URL);
          if (!res.ok) throw new Error(`HTTP ${res.status}`);
          untrusted = join(workdir, 'freetsa-tsa.crt');
          await writeFile(untrusted, res.bytes);
        }
      } catch (err) {
        add(
          'skip',
          'FreeTSA signature',
          `Could not download FreeTSA's certificates (${err.message}).`,
        );
        return null;
      }
      const root = await rootFingerprint(ca);
      const known = root === FREETSA_ROOT_SHA256;
      return {
        ca,
        untrusted,
        note: known
          ? `FreeTSA root certificate, SHA-256 ${FREETSA_ROOT_SHA256}`
          : `FreeTSA root certificate from ${ca}${root ? `, SHA-256 ${root}: compare it with freetsa.org` : ''}`,
      };
    }

    async function rootFingerprint(pemPath) {
      try {
        const pem = (await readFile(pemPath, 'utf8')).match(
          /-----BEGIN CERTIFICATE-----([\s\S]+?)-----END CERTIFICATE-----/,
        );
        return pem ? sha256Hex(Buffer.from(pem[1].replace(/\s+/g, ''), 'base64')) : null;
      } catch {
        return null;
      }
    }

    // --- 4. OpenTimestamps / Bitcoin ------------------------------------------
    const otsPath = await receipt('ots', options.ots, '.ots', record?.files?.ots);
    if (!otsPath) {
      add('skip', 'Bitcoin anchor', 'No OpenTimestamps proof for this batch yet.');
    } else {
      let proof = null;
      try {
        proof = parseOts(await readFile(otsPath));
      } catch (err) {
        add('fail', 'Bitcoin anchor', `The .ots file is unreadable (${err.message}).`);
      }
      if (proof && subject && proof.digestHex !== subject) {
        add(
          'fail',
          'Bitcoin anchor',
          `The .ots proof is for a different fingerprint (${proof.digestHex}).`,
        );
      } else if (proof) {
        const blocks = [
          ...new Map(proof.bitcoin.map((b) => [`${b.height}:${b.merkleRootHex}`, b])).values(),
        ].sort((a, b) => a.height - b.height);
        if (blocks.length === 0) {
          add(
            'info',
            'Bitcoin anchor',
            `Pending: ${proof.pending.length} calendar${proof.pending.length === 1 ? '' : 's'} will anchor it in a Bitcoin block, usually within a few hours. Run this again later.`,
          );
        } else if (offline) {
          add(
            'info',
            'Bitcoin anchor',
            `The proof leads to block ${blocks.map((b) => b.height).join(', ')}; not compared with the blockchain offline.`,
          );
        } else {
          let confirmed = null;
          for (const b of blocks) {
            const header = await block(b.height);
            if (!header) continue;
            if (header.merkleRoot === b.merkleRootHex) {
              confirmed = { ...b, ...header };
              break;
            }
            add(
              'fail',
              'Bitcoin anchor',
              `The proof's path for block ${b.height} does not match that block's merkle root (${header.source}).`,
            );
          }
          if (confirmed)
            add(
              'pass',
              'Bitcoin anchor',
              `This fingerprint is committed in Bitcoin block ${confirmed.height}, mined ${utc(confirmed.time)} (merkle root checked against ${confirmed.source}).`,
            );
          else if (!checks.some((c) => c.name === 'Bitcoin anchor'))
            add(
              'skip',
              'Bitcoin anchor',
              `Could not reach a block explorer to check block ${blocks[0].height}.`,
            );
        }
      }

      // The reference client, when installed, as a second opinion.
      const otsClient = options.otsClient === false ? null : sys.which('ots');
      if (!otsClient) {
        add(
          'skip',
          'ots verify',
          `The OpenTimestamps client is not installed (pip install opentimestamps-client), or drop the .ots file on opentimestamps.org.`,
        );
      } else if (!manifestPath) {
        add('skip', 'ots verify', 'Needs the batch file, which is not published yet.');
      } else {
        const out = await sys.run(otsClient, ['verify', '-f', manifestPath, otsPath], {
          timeoutMs: 120_000,
        });
        const text = (out.stdout + out.stderr).trim();
        if (out.code === 0 && /Success!/i.test(text)) add('pass', 'ots verify', lastLine(text));
        else if (/does not match|bad|invalid/i.test(text) && !/bitcoin node|connect/i.test(text))
          add('fail', 'ots verify', lastLine(text));
        else
          add(
            'warn',
            'ots verify',
            `${lastLine(text) || `exit code ${out.code}`} (the client needs a Bitcoin node or explorer; the built-in check above does not).`,
          );
      }
    }

    async function block(height) {
      for (const base of EXPLORERS) {
        try {
          const hashRes = await get(`${base}/block-height/${height}`);
          if (!hashRes.ok) continue;
          const hash = hashRes.bytes.toString('utf8').trim();
          if (!SHA.test(hash)) continue;
          const blockRes = await get(`${base}/block/${hash}`);
          if (!blockRes.ok) continue;
          const body = JSON.parse(blockRes.bytes.toString('utf8'));
          if (typeof body.merkle_root !== 'string' || typeof body.timestamp !== 'number') continue;
          return {
            hash,
            merkleRoot: body.merkle_root,
            time: new Date(body.timestamp * 1000),
            source: new URL(base).host,
          };
        } catch {
          // next explorer
        }
      }
      return null;
    }

    // --- 5. verdict -------------------------------------------------------------
    const failed = checks.some((c) => c.status === 'fail');
    const tsaPassed = checks.some((c) => c.status === 'pass' && / timestamp$/.test(c.name));
    const filePassed = checks.some((c) => c.status === 'pass' && c.name === 'Fingerprint');
    if (failed) {
      report.verdict = 'FAIL';
      report.summary = 'At least one check failed. Do not trust this batch file as sealed.';
    } else if (tsaPassed && filePassed) {
      report.verdict = 'PASS';
      report.summary = `This batch file existed, exactly as it is, before kick-off${kickoff ? ` at ${utc(kickoff)}` : ''}.`;
    } else if (tsaPassed && !manifestBytes) {
      report.verdict = 'PASS';
      report.summary =
        'The fingerprint was signed before kick-off. The batch file comes after the matches; run this again then to check the picks in it.';
    } else {
      report.verdict = 'INCOMPLETE';
      report.summary =
        'Not enough could be checked to confirm the batch was sealed before kick-off.';
    }
    return report;
  } finally {
    if (!keepWorkdir) {
      await rm(workdir, { recursive: true, force: true });
      report.workdir = null;
    }
  }
}

function lastLine(text) {
  return (
    text
      .split('\n')
      .map((l) => l.trim())
      .filter((l) => l && !/^Using configuration from|process_include|conf_def\.c/.test(l))
      .pop() ?? ''
  );
}

function opensslHint(provider, manifestPath, tsrPath) {
  const data = manifestPath ? `-data ${basename(manifestPath)}` : '-digest <fingerprint>';
  return provider === 'freetsa'
    ? `openssl ts -verify ${data} -in ${basename(tsrPath)} -CAfile cacert.pem -untrusted tsa.crt`
    : `openssl ts -verify ${data} -in ${basename(tsrPath)} -CAfile /etc/ssl/cert.pem`;
}
