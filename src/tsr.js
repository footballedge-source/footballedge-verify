import { Buffer } from 'node:buffer';
/**
 * RFC 3161 time-stamp responses (`.tsr` files) — just enough DER to read
 * what the authority signed: the status, the SHA-256 it was given and the
 * time it signed (`genTime`).
 *
 * This does NOT check the signature. That is `openssl ts -verify` with the
 * authority's certificates (see `openssl.js`); this module answers the
 * question openssl leaves to you: "is this token about *my* file, and when?"
 */

/**
 * @typedef {{ tag: number, value: Buffer, children: DerNode[] }} DerNode
 */

/** @returns {{ node: DerNode, next: number }} */
function readNode(buf, offset) {
  if (offset + 2 > buf.length) throw new Error('DER: truncated');
  const tag = buf[offset];
  if ((tag & 0x1f) === 0x1f) throw new Error('DER: multi-byte tags are not supported');
  let pos = offset + 2;
  let length = buf[offset + 1];
  if (length & 0x80) {
    const count = length & 0x7f;
    if (count === 0 || count > 4) throw new Error('DER: unsupported length');
    if (pos + count > buf.length) throw new Error('DER: truncated');
    length = 0;
    for (let i = 0; i < count; i += 1) length = length * 256 + buf[pos + i];
    pos += count;
  }
  const end = pos + length;
  if (end > buf.length) throw new Error('DER: length past the end');
  const value = buf.subarray(pos, end);
  const children = [];
  if (tag & 0x20) {
    let at = 0;
    while (at < value.length) {
      const { node, next } = readNode(value, at);
      children.push(node);
      at = next;
    }
  }
  return { node: { tag, value, children }, next: end };
}

/** Parses one DER value that fills `buf` exactly. */
export function parseDer(buf) {
  const { node, next } = readNode(buf, 0);
  if (next !== buf.length) throw new Error('DER: trailing bytes');
  return node;
}

function child(node, index, tag, what) {
  const c = node?.children[index];
  if (!c || c.tag !== tag) throw new Error(`RFC 3161: unexpected structure at ${what}`);
  return c;
}

/** `YYYYMMDDHHMMSS[.fff]Z` → Date. */
export function parseGeneralizedTime(text) {
  const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:[.,](\d{1,9}))?Z$/.exec(text);
  if (!m) throw new Error(`RFC 3161: unsupported GeneralizedTime ${text}`);
  const ms = m[7] ? Math.floor(Number(`0.${m[7]}`) * 1000) : 0;
  return new Date(Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6], ms));
}

const SHA256_OID = '608648016503040201'; // 2.16.840.1.101.3.4.2.1

/**
 * Reads a `TimeStampResp`.
 *
 * @param {Buffer} tsr
 * @returns {{ status: number, granted: boolean, hashAlgorithm?: string, digestHex?: string, genTime?: Date, serial?: string }}
 */
export function parseTimeStampResponse(tsr) {
  const resp = parseDer(tsr);
  if (resp.tag !== 0x30) throw new Error('RFC 3161: not a TimeStampResp');
  const statusInfo = child(resp, 0, 0x30, 'status');
  const statusBytes = child(statusInfo, 0, 0x02, 'status.status').value;
  const status = statusBytes.readUIntBE(0, Math.min(6, statusBytes.length));
  const granted = status === 0 || status === 1;
  if (!granted) return { status, granted };

  const token = child(resp, 1, 0x30, 'timeStampToken');
  const signedData = child(child(token, 1, 0xa0, 'content'), 0, 0x30, 'SignedData');
  const encap = child(signedData, 2, 0x30, 'encapContentInfo');
  const eContent = child(encap, 1, 0xa0, 'eContent').children[0];
  if (!eContent) throw new Error('RFC 3161: empty eContent');
  // DER says primitive; tolerate a constructed (BER) OCTET STRING.
  const tstBytes =
    eContent.tag === 0x04
      ? eContent.value
      : eContent.tag === 0x24
        ? Buffer.concat(eContent.children.map((c) => c.value))
        : null;
  if (!tstBytes) throw new Error('RFC 3161: eContent is not an OCTET STRING');

  const tst = parseDer(tstBytes);
  const imprint = child(tst, 2, 0x30, 'messageImprint');
  const algorithm = child(child(imprint, 0, 0x30, 'hashAlgorithm'), 0, 0x06, 'hashAlgorithm.oid');
  const digest = child(imprint, 1, 0x04, 'hashedMessage').value;
  const serial = child(tst, 3, 0x02, 'serialNumber').value.toString('hex');
  const genTime = parseGeneralizedTime(child(tst, 4, 0x18, 'genTime').value.toString('ascii'));
  return {
    status,
    granted,
    hashAlgorithm:
      algorithm.value.toString('hex') === SHA256_OID
        ? 'sha256'
        : `oid:${algorithm.value.toString('hex')}`,
    digestHex: digest.toString('hex'),
    genTime,
    serial,
  };
}
