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

Output for the example batch:

```
footballedge-verify 0.1.0

Batch      6ad532063ef1a0ab2563849f
Kick-off   2026-10-18 21:00 UTC
File       footballedge-picks-20261018T2100Z-3149562304db.json (2822 bytes)
SHA-256    3149562304dbff907bb89ebb52f0c03561871e95fd4adf729b6b4a880baf2bd1

PASS  Fingerprint         SHA-256 of the file is 3149…2bd1, the published fingerprint.
PASS  Batch file          Canonical footballedge-pick-manifest/1: 6 calls (2 picks, 4 no pick), kick-off 2026-10-18 21:00:00 UTC.
PASS  FreeTSA timestamp   Signs this fingerprint at 2026-10-18 20:54:30 UTC, 5 min 30 s before kick-off.
PASS  FreeTSA signature   openssl ts -verify: OK (FreeTSA root certificate, SHA-256 a6379e7c…aabc).
PASS  DigiCert timestamp  Signs this fingerprint at 2026-10-18 20:54:30 UTC, 5 min 30 s before kick-off.
PASS  DigiCert signature  openssl ts -verify: OK (trusted roots from /etc/ssl/certs/ca-certificates.crt).
PASS  Bitcoin anchor      This fingerprint is committed in Bitcoin block 972055, mined 2026-10-18 21:09:11 UTC (merkle root checked against mempool.space).
SKIP  ots verify          The OpenTimestamps client is not installed (pip install opentimestamps-client), or drop the .ots file on opentimestamps.org.

Calls sealed in this batch
  no pick  Estudiantes L.P. v San Lorenzo · 1X2: home win (49%)
  pick     Estudiantes L.P. v San Lorenzo · Over/Under 2.5: under 2.5 (71%)
  …

Result: PASS — This batch file existed, exactly as it is, before kick-off at 2026-10-18 21:00:00 UTC.
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

## Development

```bash
npm test     # node --test, uses the real openssl when installed
```

`test/fixtures` holds a real sealed batch as the API served it, FreeTSA's public certificates and
the two Bitcoin block headers its proof leads to, so the tests run offline.
