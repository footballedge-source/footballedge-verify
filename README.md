# footballedge-verify

Check, on your own computer, that a [FootballEdge](https://footballedge.io) pick was written down before
kick-off and has not been changed since.

FootballEdge seals every batch of picks about five minutes before kick-off: all the calls for the
matches kicking off at that minute go into one JSON file (the **batch file**), its SHA-256 fingerprint
is sent to two RFC 3161 timestamp authorities ([FreeTSA](https://freetsa.org) and
[DigiCert](https://www.digicert.com)) and to the [OpenTimestamps](https://opentimestamps.org)
calendars, which anchor it in the Bitcoin blockchain. The batch file is published once its matches
are over. This tool checks all of that without trusting FootballEdge's servers for anything but the
download.

- No dependencies. Node.js 20 or later.
- Uses `openssl` (to check the authorities' signatures) and `ots` (the OpenTimestamps client) when
  they are installed, and tells you how to run the same checks by hand when they are not.
- MIT licence.

## Usage

```bash
# a batch by id (from https://footballedge.io/en/results/proof)
npx footballedge-verify 6ad532063ef1a0ab2563849f

# or by its link, or its fingerprint
npx footballedge-verify https://footballedge.io/en/results/proof/6ad532063ef1a0ab2563849f
npx footballedge-verify 3149562304dbff907bb89ebb52f0c03561871e95fd4adf729b6b4a880baf2bd1

# a batch file you downloaded earlier (the receipts are fetched, or read from
# <file>.ots, <file>.freetsa.tsr and <file>.digicert.tsr next to it)
npx footballedge-verify ./footballedge-picks-20261018T2100Z-3149562304db.json

# keep the downloaded files, to repeat the checks by hand
npx footballedge-verify 6ad532063ef1a0ab2563849f --dir ./batch
```

From a clone instead of npm: `node bin/footballedge-verify.js <batch>`.

Output of a real run (batch `6ad6595765497923a6ea0c47`, kick-off 19 October 2026 18:00 UTC,
checked on 20 October 2026):

```
$ npx footballedge-verify 6ad6595765497923a6ea0c47
footballedge-verify 0.1.0

Batch      6ad6595765497923a6ea0c47
Kick-off   2026-10-19 18:00 UTC
File       footballedge-picks-20261019T1800Z-63bbc91962c5.json (2692 bytes)
SHA-256    63bbc91962c5b4de36929ae12eb4998054c0aa17c60b747e2a965f5f126418ab

PASS  Fingerprint         SHA-256 of the file is 63bbc91962c5b4de36929ae12eb4998054c0aa17c60b747e2a965f5f126418ab, the published fingerprint.
PASS  Batch file          Canonical footballedge-pick-manifest/1: 6 calls (2 picks, 4 no pick), kick-off 2026-10-19 18:00:00 UTC.
PASS  FreeTSA timestamp   Signs this fingerprint at 2026-10-19 17:54:31 UTC, 5 min 29 s before kick-off.
PASS  FreeTSA signature   openssl ts -verify: OK (FreeTSA root certificate, SHA-256 a6379e7cecc05faa3cbf076013d745e327bbbaa38c0b9af22469d4701d18aabc).
PASS  DigiCert timestamp  Signs this fingerprint at 2026-10-19 17:54:31 UTC, 5 min 29 s before kick-off.
PASS  DigiCert signature  openssl ts -verify: OK (trusted roots from /etc/ssl/certs/ca-certificates.crt).
PASS  Bitcoin anchor      This fingerprint is committed in Bitcoin block 972191, mined 2026-10-19 18:25:47 UTC (merkle root checked against mempool.space).
SKIP  ots verify          The OpenTimestamps client is not installed (pip install opentimestamps-client), or drop the .ots file on opentimestamps.org.

Calls sealed in this batch
  no pick  FC Voluntari v FCSB · 1X2: away win (53%)
           https://footballedge.io/en/matches/fc-voluntari-vs-fcsb-2026-10-19
  no pick  FC Voluntari v FCSB · Over/Under 2.5: over 2.5 (65%)
           https://footballedge.io/en/matches/fc-voluntari-vs-fcsb-2026-10-19
  no pick  Al Shabab v Al-Faisaly FC · 1X2: home win (54%)
           https://footballedge.io/en/matches/al-shabab-vs-al-faisaly-fc-2026-10-19
  no pick  Al Shabab v Al-Faisaly FC · Over/Under 2.5: over 2.5 (59%)
           https://footballedge.io/en/matches/al-shabab-vs-al-faisaly-fc-2026-10-19
  pick     Al-Hilal Saudi FC v Al-Hazm · 1X2: home win (83%)
           https://footballedge.io/en/matches/al-hilal-saudi-fc-vs-al-hazm-2026-10-19
  pick     Al-Hilal Saudi FC v Al-Hazm · Over/Under 2.5: over 2.5 (73%)
           https://footballedge.io/en/matches/al-hilal-saudi-fc-vs-al-hazm-2026-10-19
  Each pick must appear with the same call and percentage on the match page and the track record.

Batch page:    https://footballedge.io/en/results/proof/6ad6595765497923a6ea0c47
Track record:  https://footballedge.io/en/results

Result: PASS — This batch file existed, exactly as it is, before kick-off at 2026-10-19 18:00:00 UTC.
What this shows: the file existed unchanged at the signed time. What it does not show: how the picks are made, or whether they will win.
```

Exit code: `0` pass, `1` a check failed, `2` usage error, `3` not enough could be checked (for
example offline without the receipts). `--json` prints the whole report as JSON.

## What it checks

1. **Fingerprint.** SHA-256 of the batch file equals the fingerprint FootballEdge published for the
   batch. Change one character and it no longer does.
2. **Batch file.** It is a `footballedge-pick-manifest/1` file in canonical JSON (sorted keys,
   two-space indent, integers only), so the same calls always give the same bytes.
3. **Timestamp tokens (RFC 3161).** Each `.tsr` file is read directly: it must be granted, for SHA-256,
   for *this* fingerprint, with a signing time (`genTime`) before kick-off. Then
   `openssl ts -verify` checks the authority's signature against its certificates: FreeTSA's
   `cacert.pem` and `tsa.crt` (downloaded from freetsa.org; the root's SHA-256 is printed so you can
   compare it), and DigiCert's root from your system's certificate store.
4. **Bitcoin (OpenTimestamps).** The `.ots` proof is replayed operation by operation from the
   fingerprint to each Bitcoin attestation; the result must equal that block's merkle root, fetched
   from mempool.space (blockstream.info as a fallback). If the `ots` client is installed, `ots verify`
   runs too. A fresh batch shows as *pending* for the first few hours.

Before a batch's matches are over, its batch file is not public yet. The tool then checks the
receipts against the published fingerprint and tells you to come back after full time.

## By hand, without this tool

```bash
B=https://api.footballedge.io/proofs/6ad532063ef1a0ab2563849f
curl -sOJ $B/manifest.json; curl -sOJ $B/manifest.json.ots; curl -sOJ $B/freetsa.tsr; curl -sOJ $B/digicert.tsr
F=footballedge-picks-20261018T2100Z-3149562304db.json

shasum -a 256 $F                       # Windows: certutil -hashfile %F% SHA256

curl -sO https://freetsa.org/files/cacert.pem; curl -sO https://freetsa.org/files/tsa.crt
openssl ts -verify -data $F -in $F.freetsa.tsr -CAfile cacert.pem -untrusted tsa.crt
openssl ts -verify -data $F -in $F.digicert.tsr -CAfile /etc/ssl/cert.pem   # Debian/Ubuntu: /etc/ssl/certs/ca-certificates.crt
openssl ts -reply -in $F.freetsa.tsr -text                                  # shows the signed time

ots verify -f $F $F.ots                # pip install opentimestamps-client, or use opentimestamps.org
```

## The public API it uses

All read-only, no key, no sign-in:

| Request | Answer |
|---|---|
| `GET /proofs/<id>` | The batch record: fingerprint, kick-off, timestamp times, Bitcoin status, file links. |
| `GET /proofs/sha256/<fingerprint>` | The same record, looked up by fingerprint. |
| `GET /proofs/<id>/manifest.json` | The batch file, byte for byte what was hashed (403 until the matches are over). |
| `GET /proofs/<id>/freetsa.tsr`, `/digicert.tsr` | The authorities' RFC 3161 answers, as received. |
| `GET /proofs/<id>/manifest.json.ots` | The OpenTimestamps proof. |

Base URL: `https://api.footballedge.io`.

## What this proves, and what it doesn't

It proves **timing and integrity**: the batch file existed, exactly as it is, at the time the
authorities signed, which is before kick-off. Nobody, FootballEdge included, can change a pick in it
afterwards without the check failing. Each batch lists every call for its matches, including the
ones marked "no pick".

It does **not** prove that the picks are any good, it is not an audit of how they are made, and it
says nothing about picks from before 16 October 2026, which were not sealed. The hit rates are on
the [track record](https://footballedge.io/en/results).

FootballEdge is for adults (18+). Predictions are statistical estimates, never a promise of a
result. If betting stops being fun, free help is at [GamCare](https://www.gamcare.org.uk) (UK),
[ncpgambling.org](https://www.ncpgambling.org) (US) or a service in your country.

## Troubleshooting

- **"Could not reach https://api.footballedge.io (fetch failed)"** behind a corporate proxy: Node's
  `fetch` ignores `HTTPS_PROXY` unless you ask it to. On Node 24 run
  `NODE_USE_ENV_PROXY=1 npx footballedge-verify …`; on older versions download the four files with
  `curl` (see "By hand") and run `npx footballedge-verify ./<file>.json --offline --sha256 <fingerprint>`.
- **"SKIP FreeTSA signature"**: `openssl` is not installed or not on your `PATH`. The token's contents
  are still checked; install OpenSSL (it ships with macOS and most Linux distributions; on Windows
  use Git Bash or WSL) to check the signature too.
- **"PENDING Bitcoin anchor"**: the batch was sealed in the last few hours and its Bitcoin block is
  not mined yet. Run the tool again later.

## Development

```bash
npm test     # node --test, uses the real openssl when installed
```

`test/fixtures` holds a real sealed batch as the API served it, FreeTSA's public certificates and
the two Bitcoin block headers its proof leads to, so the tests run offline.
