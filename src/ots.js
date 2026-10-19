import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';

/**
 * OpenTimestamps detached proofs (`.ots` files): read one, replay every
 * operation from the file's SHA-256 down to each attestation, and report
 *
 *  - the calendars still waiting for Bitcoin (pending attestations);
 *  - for each Bitcoin attestation, the block height and the merkle root the
 *    path arrives at — which must equal that block's merkle root.
 *
 * Byte layout as in python-opentimestamps (`core/timestamp.py`, `core/op.py`,
 * `core/notary.py`), which the official `ots` client and opentimestamps.org
 * use. No dependency.
 */

export const OTS_HEADER_MAGIC = Buffer.from(
  '004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294',
  'hex',
);

const TAG_ATTESTATION = 0x00;
const TAG_FORK = 0xff;
const OP_SHA1 = 0x02;
const OP_RIPEMD160 = 0x03;
const OP_SHA256 = 0x08;
const OP_KECCAK256 = 0x67;
const OP_APPEND = 0xf0;
const OP_PREPEND = 0xf1;
const OP_REVERSE = 0xf2;
const OP_HEXLIFY = 0xf3;

const PENDING_TAG = Buffer.from('83dfe30d2ef90c8e', 'hex');
const BITCOIN_TAG = Buffer.from('0588960d73d71901', 'hex');

const MAX_DEPTH = 256;

class Reader {
  constructor(buf) {
    this.buf = buf;
    this.pos = 0;
  }
  byte() {
    if (this.pos >= this.buf.length) throw new Error('OTS: truncated');
    return this.buf[this.pos++];
  }
  bytes(n) {
    if (this.pos + n > this.buf.length) throw new Error('OTS: truncated');
    const out = this.buf.subarray(this.pos, this.pos + n);
    this.pos += n;
    return Buffer.from(out);
  }
  varuint() {
    let value = 0;
    let shift = 0;
    for (;;) {
      const b = this.byte();
      value += (b & 0x7f) * 2 ** shift;
      if (!(b & 0x80)) return value;
      shift += 7;
      if (shift > 49) throw new Error('OTS: varuint too long');
    }
  }
  varbytes(max) {
    const n = this.varuint();
    if (n > max) throw new Error('OTS: varbytes too long');
    return this.bytes(n);
  }
  get done() {
    return this.pos >= this.buf.length;
  }
}

function hash(algorithm, msg) {
  return createHash(algorithm).update(msg).digest();
}

function applyOp(tag, arg, msg) {
  switch (tag) {
    case OP_APPEND:
      return Buffer.concat([msg, arg]);
    case OP_PREPEND:
      return Buffer.concat([arg, msg]);
    case OP_SHA256:
      return hash('sha256', msg);
    case OP_SHA1:
      return hash('sha1', msg);
    case OP_RIPEMD160:
      return hash('ripemd160', msg);
    case OP_REVERSE:
      return Buffer.from(msg).reverse();
    case OP_HEXLIFY:
      return Buffer.from(msg.toString('hex'), 'ascii');
    case OP_KECCAK256:
      throw new Error('OTS: keccak256 is not supported by this verifier');
    default:
      throw new Error(`OTS: unknown operation 0x${tag.toString(16)}`);
  }
}

function readAttestation(r) {
  const tag = r.bytes(8);
  const payload = r.varbytes(8192);
  if (tag.equals(PENDING_TAG)) {
    return { kind: 'pending', uri: new Reader(payload).varbytes(1000).toString('utf8') };
  }
  if (tag.equals(BITCOIN_TAG)) return { kind: 'bitcoin', height: new Reader(payload).varuint() };
  return { kind: 'unknown', tag: tag.toString('hex') };
}

/** Reads a timestamp tree, calling `found(attestation, msg)` at every attestation. */
function readTimestamp(r, msg, found, depth = 0) {
  if (depth > MAX_DEPTH) throw new Error('OTS: too deep');
  const handle = (tag) => {
    if (tag === TAG_ATTESTATION) {
      found(readAttestation(r), msg);
      return;
    }
    const binary = tag === OP_APPEND || tag === OP_PREPEND;
    if (
      !binary &&
      ![OP_SHA1, OP_RIPEMD160, OP_SHA256, OP_KECCAK256, OP_REVERSE, OP_HEXLIFY].includes(tag)
    )
      throw new Error(`OTS: unknown operation 0x${tag.toString(16)}`);
    const arg = binary ? r.varbytes(4096) : Buffer.alloc(0);
    readTimestamp(r, applyOp(tag, arg, msg), found, depth + 1);
  };
  let tag = r.byte();
  while (tag === TAG_FORK) {
    handle(r.byte());
    tag = r.byte();
  }
  handle(tag);
}

/**
 * Reads a detached `.ots` proof.
 *
 * @param {Buffer} bytes
 * @returns {{
 *   digestHex: string,
 *   pending: string[],
 *   bitcoin: Array<{ height: number, merkleRootHex: string }>,
 *   unknown: number,
 * }} `merkleRootHex` is in the byte order block explorers print (reversed from the header).
 */
export function parseOts(bytes) {
  if (
    bytes.length < OTS_HEADER_MAGIC.length ||
    !bytes.subarray(0, OTS_HEADER_MAGIC.length).equals(OTS_HEADER_MAGIC)
  )
    throw new Error('OTS: not an OpenTimestamps proof');
  const r = new Reader(bytes);
  r.bytes(OTS_HEADER_MAGIC.length);
  if (r.varuint() !== 1) throw new Error('OTS: unsupported version');
  if (r.byte() !== OP_SHA256) throw new Error('OTS: only SHA-256 file hashes are supported');
  const digest = r.bytes(32);
  const pending = [];
  const bitcoin = [];
  let unknown = 0;
  readTimestamp(r, digest, (attestation, msg) => {
    if (attestation.kind === 'pending') pending.push(attestation.uri);
    else if (attestation.kind === 'bitcoin')
      bitcoin.push({
        height: attestation.height,
        merkleRootHex: Buffer.from(msg).reverse().toString('hex'),
      });
    else unknown += 1;
  });
  if (!r.done) throw new Error('OTS: trailing bytes');
  return {
    digestHex: digest.toString('hex'),
    pending: [...new Set(pending)].sort(),
    bitcoin,
    unknown,
  };
}
