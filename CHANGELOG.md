# Changelog

All notable changes to `footballedge-verify`. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/).

## [0.1.0] — 2026-10-20

First public version.

### Added

- `footballedge-verify <batch id | fingerprint | batch link | batch file>`: checks a sealed
  FootballEdge batch end to end and prints PASS / FAIL / PENDING / SKIP per check.
- Fingerprint: SHA-256 of the batch file against the published fingerprint.
- Batch file: the `footballedge-pick-manifest/1` format in canonical JSON, with its calls listed.
- RFC 3161: reads the FreeTSA and DigiCert tokens (granted, SHA-256, this fingerprint, signing time
  before kick-off) and runs `openssl ts -verify` against FreeTSA's certificates and the system's
  trusted roots when OpenSSL is installed.
- OpenTimestamps: replays the `.ots` proof to each Bitcoin attestation and checks the block's
  merkle root against mempool.space (blockstream.info as a fallback); runs `ots verify` when the
  OpenTimestamps client is installed.
- `--offline` with local files, `--dir` to keep the downloads, `--json` for the full report.
- Exit codes: `0` pass, `1` a check failed, `2` usage error, `3` not enough could be checked.
- No runtime dependencies; Node.js 20 or later.
