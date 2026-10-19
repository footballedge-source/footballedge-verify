#!/usr/bin/env node
import process from 'node:process';
import { parseArgs } from 'node:util';
import { exitCode, formatReport } from '../src/report.js';
import { DEFAULT_API, UsageError, VERSION, verify } from '../src/verify.js';

const HELP = `footballedge-verify ${VERSION} — check that a FootballEdge pick was sealed before kick-off

Usage
  footballedge-verify <batch id | fingerprint | batch link | batch file> [options]

Examples
  npx footballedge-verify 6ad532063ef1a0ab2563849f
  npx footballedge-verify https://footballedge.io/en/results/proof/6ad532063ef1a0ab2563849f
  npx footballedge-verify ./footballedge-picks-20261018T2100Z-3149562304db.json
  npx footballedge-verify ./batch.json --offline --sha256 <fingerprint> --freetsa-ca cacert.pem --freetsa-cert tsa.crt

What it checks
  1. SHA-256 of the batch file = the published fingerprint
  2. The FreeTSA and DigiCert RFC 3161 tokens sign that fingerprint before kick-off
     (and, with openssl installed, that their signatures are valid)
  3. The OpenTimestamps proof leads from the fingerprint to a Bitcoin block's merkle root
     (and runs \`ots verify\` too when the OpenTimestamps client is installed)

Options
  --api <url>           API base (default ${DEFAULT_API})
  --dir <folder>        keep the downloaded files here (default: a temporary folder, removed)
  --offline             no network: local files only (receipts next to the file: <file>.ots,
                        <file>.freetsa.tsr, <file>.digicert.tsr)
  --sha256 <hex>        the published fingerprint, for --offline
  --ots <file>          the .ots proof            --freetsa-tsr <file>   FreeTSA's .tsr
  --digicert-tsr <file> DigiCert's .tsr
  --freetsa-ca <file>   FreeTSA cacert.pem        --freetsa-cert <file>  FreeTSA tsa.crt
                        (default: downloaded from freetsa.org)
  --ca-bundle <file>    trusted roots for DigiCert (default: your system's bundle)
  --no-openssl          do not run openssl        --no-ots              do not run ots
  --json                print the report as JSON
  -h, --help            this help                 -v, --version

Exit code: 0 pass, 1 a check failed, 2 usage error, 3 not enough could be checked.
`;

async function main(argv) {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      api: { type: 'string' },
      site: { type: 'string' },
      dir: { type: 'string' },
      offline: { type: 'boolean' },
      sha256: { type: 'string' },
      ots: { type: 'string' },
      'freetsa-tsr': { type: 'string' },
      'digicert-tsr': { type: 'string' },
      'freetsa-ca': { type: 'string' },
      'freetsa-cert': { type: 'string' },
      'ca-bundle': { type: 'string' },
      'no-openssl': { type: 'boolean' },
      'no-ots': { type: 'boolean' },
      json: { type: 'boolean' },
      help: { type: 'boolean', short: 'h' },
      version: { type: 'boolean', short: 'v' },
    },
  });
  if (values.help) return (process.stdout.write(HELP), 0);
  if (values.version) return (process.stdout.write(`${VERSION}\n`), 0);
  if (positionals.length !== 1)
    throw new UsageError('Give exactly one batch id, fingerprint, link or file. See --help.');

  const report = await verify(positionals[0], {
    api: values.api,
    site: values.site,
    dir: values.dir,
    offline: values.offline,
    sha256: values.sha256,
    ots: values.ots,
    freetsaTsr: values['freetsa-tsr'],
    digicertTsr: values['digicert-tsr'],
    freetsaCa: values['freetsa-ca'],
    freetsaCert: values['freetsa-cert'],
    caBundle: values['ca-bundle'],
    openssl: !values['no-openssl'],
    otsClient: !values['no-ots'],
  });
  if (values.json) process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  else
    process.stdout.write(
      formatReport(report, { colour: process.stdout.isTTY && !process.env.NO_COLOR }),
    );
  return exitCode(report);
}

main(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = code;
  },
  (err) => {
    process.stderr.write(`footballedge-verify: ${err.message}\n`);
    process.exitCode =
      err instanceof UsageError || err?.code?.startsWith?.('ERR_PARSE_ARGS') ? 2 : 1;
  },
);
