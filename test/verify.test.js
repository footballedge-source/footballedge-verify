import process from 'node:process';
import { Buffer } from 'node:buffer';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { copyFile, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalJson, readManifest } from '../src/manifest.js';
import { parseOts } from '../src/ots.js';
import { exitCode, formatReport } from '../src/report.js';
import { which } from '../src/system.js';
import { parseTimeStampResponse } from '../src/tsr.js';
import { duration, parseTarget, sha256Hex, UsageError, verify } from '../src/verify.js';

/**
 * Fixtures: batch 6ad532063ef1a0ab2563849f (kick-off 18 Oct 2026 21:00 UTC)
 * exactly as https://api.footballedge.io served it on 19 Oct 2026, FreeTSA's
 * public certificates, and the two Bitcoin block headers its proof leads to.
 */
const here = dirname(fileURLToPath(import.meta.url));
const fx = (name) => join(here, 'fixtures', name);
const bytes = (name) => readFileSync(fx(name));
const record = JSON.parse(readFileSync(fx('proof.json'), 'utf8'));
const blocks = JSON.parse(readFileSync(fx('blocks.json'), 'utf8'));
const ID = record.id;
const SHA = '3149562304dbff907bb89ebb52f0c03561871e95fd4adf729b6b4a880baf2bd1';
const API = 'https://api.test';
const OPENSSL = which('openssl');

/** A fetch that serves the fixtures like the API, FreeTSA and a block explorer. */
function fakeFetch({ manifestStatus = 200, recordOverride = {}, blockOverride = {} } = {}) {
  const body = { ...record, ...recordOverride };
  const routes = new Map([
    [`${API}/proofs/${ID}`, () => [200, JSON.stringify(body)]],
    [`${API}/proofs/sha256/${SHA}`, () => [200, JSON.stringify(body)]],
    [
      `${API}${record.files.manifest}`,
      () =>
        manifestStatus === 200
          ? [200, bytes('manifest.json')]
          : [manifestStatus, '{"code":"NOT_YET_PUBLIC"}'],
    ],
    [`${API}${record.files.ots}`, () => [200, bytes('manifest.json.ots')]],
    [`${API}${record.files.tsr.freetsa}`, () => [200, bytes('freetsa.tsr')]],
    [`${API}${record.files.tsr.digicert}`, () => [200, bytes('digicert.tsr')]],
    ['https://freetsa.org/files/cacert.pem', () => [200, bytes('freetsa-cacert.pem')]],
    ['https://freetsa.org/files/tsa.crt', () => [200, bytes('freetsa-tsa.crt')]],
  ]);
  for (const [height, b] of Object.entries(blocks)) {
    if (height.startsWith('_')) continue;
    const block = { ...b, ...(blockOverride[height] ?? {}) };
    routes.set(`https://mempool.space/api/block-height/${height}`, () => [200, block.hash]);
    routes.set(`https://mempool.space/api/block/${block.hash}`, () => [200, JSON.stringify(block)]);
  }
  const calls = [];
  const fetch = async (url) => {
    calls.push(url);
    const route = routes.get(url);
    const [status, payload] = route ? route() : [404, 'not found'];
    const buf = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);
    return {
      status,
      ok: status >= 200 && status < 300,
      arrayBuffer: async () => buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.length),
    };
  };
  return { fetch, calls };
}

/** The real `openssl` when installed; never the real `ots` (a test must not need a Bitcoin node). */
const system = (fetch, extra = {}) => ({
  fetch,
  which: (cmd) => (cmd === 'openssl' ? OPENSSL : null),
  ...extra,
});
const status = (report, name) => report.checks.find((c) => c.name === name)?.status;

test('targets: id, fingerprint, links, files', () => {
  assert.deepEqual(parseTarget(ID.toUpperCase()), { kind: 'id', value: ID });
  assert.deepEqual(parseTarget(SHA), { kind: 'sha256', value: SHA });
  assert.deepEqual(parseTarget(`https://footballedge.io/de/results/proof/${ID}`), {
    kind: 'id',
    value: ID,
  });
  assert.deepEqual(parseTarget(`https://api.footballedge.io/proofs/${ID}/manifest.json`), {
    kind: 'id',
    value: ID,
  });
  assert.deepEqual(parseTarget(`https://api.footballedge.io/proofs/sha256/${SHA}`), {
    kind: 'sha256',
    value: SHA,
  });
  assert.equal(parseTarget(fx('manifest.json')).kind, 'file');
  assert.throws(() => parseTarget('https://footballedge.io/en/results'), UsageError);
  assert.throws(() => parseTarget('no-such-file.json'), UsageError);
});

test('the .tsr files sign the batch fingerprint at the published times', () => {
  for (const provider of ['freetsa', 'digicert']) {
    const token = parseTimeStampResponse(bytes(`${provider}.tsr`));
    assert.equal(token.granted, true);
    assert.equal(token.hashAlgorithm, 'sha256');
    assert.equal(token.digestHex, SHA);
    assert.equal(
      token.genTime.toISOString(),
      record.timestamps.find((t) => t.provider === provider).time,
    );
  }
  assert.throws(() => parseTimeStampResponse(Buffer.from('not der')));
});

test('the .ots proof commits the fingerprint and leads to the block merkle roots', () => {
  const proof = parseOts(bytes('manifest.json.ots'));
  assert.equal(proof.digestHex, SHA);
  assert.equal(proof.pending.length, 4);
  assert.deepEqual(
    [...new Set(proof.bitcoin.map((b) => `${b.height}:${b.merkleRootHex}`))],
    ['972055', '972057'].map((h) => `${h}:${blocks[h].merkle_root}`),
  );
  assert.throws(() => parseOts(Buffer.from('nope')), /not an OpenTimestamps proof/);
});

test('the batch file is canonical JSON and its hash is the fingerprint', () => {
  const file = bytes('manifest.json');
  assert.equal(sha256Hex(file), SHA);
  const read = readManifest(file);
  assert.equal(read.ok, true);
  assert.equal(read.canonical, true);
  assert.equal(canonicalJson(read.manifest), file.toString('utf8'));
  assert.equal(readManifest(Buffer.from('{"a":1}')).ok, false);
  assert.equal(readManifest(Buffer.from(JSON.stringify(read.manifest))).canonical, false);
});

test('a sealed, published batch passes every check', async () => {
  const { fetch } = fakeFetch();
  const report = await verify(ID, { api: API }, system(fetch));
  assert.equal(report.verdict, 'PASS', formatReport(report));
  assert.equal(exitCode(report), 0);
  assert.equal(status(report, 'Fingerprint'), 'pass');
  assert.equal(status(report, 'Batch file'), 'pass');
  assert.equal(status(report, 'FreeTSA timestamp'), 'pass');
  assert.equal(status(report, 'DigiCert timestamp'), 'pass');
  assert.equal(status(report, 'Bitcoin anchor'), 'pass');
  assert.match(
    report.checks.find((c) => c.name === 'Bitcoin anchor').detail,
    /block 972055, mined 2026-10-18 21:09:11 UTC/,
  );
  assert.match(
    report.checks.find((c) => c.name === 'FreeTSA timestamp').detail,
    /5 min 30 s before kick-off/,
  );
  if (OPENSSL) {
    assert.equal(status(report, 'FreeTSA signature'), 'pass', formatReport(report));
    assert.equal(status(report, 'DigiCert signature'), 'pass', formatReport(report));
  }
  assert.equal(report.entries.filter((e) => e.call === 'pick').length, 2);
  assert.equal(
    report.entries[1].url,
    'https://footballedge.io/en/matches/estudiantes-l-p-vs-san-lorenzo-2026-10-18',
  );
  assert.equal(report.workdir, null, 'the temporary folder is removed');
  const text = formatReport(report);
  assert.match(text, /Result: PASS/);
  assert.doesNotMatch(text, /\bAI\b|\bmodel\b/i);
});

test('a local file is looked up by its fingerprint', async () => {
  const { fetch, calls } = fakeFetch();
  const report = await verify(fx('manifest.json'), { api: API }, system(fetch));
  assert.ok(calls.includes(`${API}/proofs/sha256/${SHA}`));
  assert.equal(report.verdict, 'PASS', formatReport(report));
});

test('a changed batch file fails: wrong fingerprint, and no receipt signs it', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'fe-verify-test-'));
  try {
    const file = join(dir, 'batch.json');
    await writeFile(
      file,
      (await readFile(fx('manifest.json'), 'utf8')).replace(
        '"probabilityPct": 71',
        '"probabilityPct": 72',
      ),
    );
    for (const [from, to] of [
      ['freetsa.tsr', '.freetsa.tsr'],
      ['digicert.tsr', '.digicert.tsr'],
      ['manifest.json.ots', '.ots'],
    ])
      await copyFile(fx(from), `${file}${to}`);
    const report = await verify(
      file,
      { offline: true, sha256: SHA },
      system(async () => assert.fail('offline must not fetch')),
    );
    assert.equal(report.verdict, 'FAIL');
    assert.equal(exitCode(report), 1);
    assert.equal(status(report, 'Fingerprint'), 'fail');
    assert.equal(status(report, 'FreeTSA timestamp'), 'fail');
    assert.equal(status(report, 'DigiCert timestamp'), 'fail');
    assert.equal(status(report, 'Bitcoin anchor'), 'fail');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('offline with receipts next to the original file passes', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'fe-verify-test-'));
  try {
    const file = join(dir, record.files.manifestName);
    await copyFile(fx('manifest.json'), file);
    for (const [from, to] of [
      ['freetsa.tsr', '.freetsa.tsr'],
      ['digicert.tsr', '.digicert.tsr'],
      ['manifest.json.ots', '.ots'],
    ])
      await copyFile(fx(from), `${file}${to}`);
    const report = await verify(
      file,
      {
        offline: true,
        sha256: SHA,
        freetsaCa: fx('freetsa-cacert.pem'),
        freetsaCert: fx('freetsa-tsa.crt'),
      },
      system(async () => assert.fail('offline must not fetch')),
    );
    assert.equal(report.verdict, 'PASS', formatReport(report));
    assert.equal(status(report, 'Bitcoin anchor'), 'info');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('before full time: the receipts are checked against the published fingerprint', async () => {
  const { fetch } = fakeFetch({ manifestStatus: 403, recordOverride: { manifestPublic: false } });
  const report = await verify(ID, { api: API }, system(fetch));
  assert.equal(status(report, 'Batch file'), 'skip');
  assert.equal(status(report, 'Fingerprint'), undefined);
  assert.equal(status(report, 'FreeTSA timestamp'), 'pass');
  if (OPENSSL) assert.equal(status(report, 'FreeTSA signature'), 'pass', formatReport(report));
  assert.equal(report.verdict, 'PASS');
  assert.match(report.summary, /after the matches/);
});

test('a signature after kick-off fails', async () => {
  const { fetch } = fakeFetch({ recordOverride: { kickoff: '2026-10-18T20:50:00.000Z' } });
  const report = await verify(ID, { api: API }, system(fetch));
  assert.equal(report.verdict, 'FAIL');
  assert.match(report.checks.find((c) => c.name === 'FreeTSA timestamp').detail, /after kick-off/);
});

test('a proof that does not lead to the block merkle root fails', async () => {
  const { fetch } = fakeFetch({
    blockOverride: {
      972055: { merkle_root: '00'.repeat(32) },
      972057: { merkle_root: '11'.repeat(32) },
    },
  });
  const report = await verify(ID, { api: API }, system(fetch));
  assert.equal(status(report, 'Bitcoin anchor'), 'fail');
  assert.equal(report.verdict, 'FAIL');
});

test('an unknown fingerprint is reported, not thrown', async () => {
  const { fetch } = fakeFetch();
  const report = await verify('0'.repeat(64), { api: API }, system(fetch));
  assert.equal(status(report, 'Published record'), 'fail');
  assert.equal(report.verdict, 'FAIL');
});

test('runs the OpenTimestamps client when it is installed', async () => {
  const { fetch } = fakeFetch();
  const runs = [];
  const report = await verify(
    ID,
    { api: API, openssl: false },
    system(fetch, {
      which: (cmd) => (cmd === 'ots' ? '/usr/bin/ots' : null),
      run: async (cmd, args) => {
        runs.push([cmd, ...args]);
        return {
          code: 0,
          stdout: '',
          stderr: 'Success! Bitcoin block 972055 attests existence as of 2026-10-18 UTC\n',
        };
      },
    }),
  );
  assert.equal(status(report, 'ots verify'), 'pass');
  assert.deepEqual(runs[0].slice(0, 3), ['/usr/bin/ots', 'verify', '-f']);
  assert.equal(
    status(report, 'FreeTSA signature'),
    undefined,
    '--no-openssl skips the signature check',
  );
});

test('durations read like a person wrote them', () => {
  assert.equal(duration(330_000), '5 min 30 s');
  assert.equal(duration(45_000), '45 s');
  assert.equal(duration(3 * 3600_000 + 60_000), '3 h 1 min');
});

const bin = join(here, '..', 'bin', 'footballedge-verify.js');
const cli = (args) =>
  new Promise((resolve) => {
    execFile(process.execPath, [bin, ...args], (error, stdout, stderr) =>
      resolve({ code: error ? error.code : 0, stdout, stderr }),
    );
  });

test('CLI: --help, usage errors and an offline run', async () => {
  const help = await cli(['--help']);
  assert.equal(help.code, 0);
  assert.match(help.stdout, /Usage/);
  assert.equal((await cli([])).code, 2);
  assert.equal((await cli(['not-a-batch'])).code, 2);

  const dir = await mkdtemp(join(tmpdir(), 'fe-verify-cli-'));
  try {
    const file = join(dir, record.files.manifestName);
    await copyFile(fx('manifest.json'), file);
    await copyFile(fx('freetsa.tsr'), `${file}.freetsa.tsr`);
    const out = await cli([
      file,
      '--offline',
      '--sha256',
      SHA,
      '--no-openssl',
      '--no-ots',
      '--json',
    ]);
    assert.equal(out.code, 0, out.stdout + out.stderr);
    const report = JSON.parse(out.stdout);
    assert.equal(report.verdict, 'PASS');
    assert.equal(report.sha256, SHA);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
