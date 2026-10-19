/**
 * The batch file (`footballedge-pick-manifest/1`): canonical JSON, so the
 * same content always has the same bytes and the same SHA-256.
 *
 *  - object keys sorted by UTF-16 code unit;
 *  - two-space indentation, `\n` line ends, one trailing `\n`;
 *  - integers only (probabilities are whole percentages);
 *  - strings escaped exactly as `JSON.stringify` does.
 */

export const MANIFEST_FORMAT = 'footballedge-pick-manifest/1';

function write(value, indent) {
  if (value === null) return 'null';
  switch (typeof value) {
    case 'string':
      return JSON.stringify(value);
    case 'boolean':
      return value ? 'true' : 'false';
    case 'number':
      if (!Number.isSafeInteger(value)) throw new Error(`not canonical: number ${value}`);
      return Object.is(value, -0) ? '0' : String(value);
    case 'object': {
      const inner = `${indent}  `;
      if (Array.isArray(value)) {
        if (value.length === 0) return '[]';
        return `[\n${value.map((v) => `${inner}${write(v, inner)}`).join(',\n')}\n${indent}]`;
      }
      const keys = Object.keys(value).sort();
      if (keys.length === 0) return '{}';
      const fields = keys.map((k) => `${inner}${JSON.stringify(k)}: ${write(value[k], inner)}`);
      return `{\n${fields.join(',\n')}\n${indent}}`;
    }
    default:
      throw new Error(`not canonical: ${typeof value}`);
  }
}

/** The canonical text of a parsed JSON value. */
export function canonicalJson(value) {
  return `${write(value, '')}\n`;
}

/**
 * Reads a batch file and says whether it is a well-formed, canonical
 * FootballEdge manifest.
 *
 * @param {Buffer} bytes
 * @returns {{ ok: true, manifest: object, canonical: boolean } | { ok: false, error: string }}
 */
export function readManifest(bytes) {
  let manifest;
  try {
    manifest = JSON.parse(bytes.toString('utf8'));
  } catch (err) {
    return { ok: false, error: `not JSON (${err.message})` };
  }
  if (!manifest || typeof manifest !== 'object' || manifest.format !== MANIFEST_FORMAT)
    return { ok: false, error: `not a ${MANIFEST_FORMAT} file` };
  if (!Array.isArray(manifest.entries) || typeof manifest.kickoff !== 'string')
    return { ok: false, error: 'entries or kickoff missing' };
  let canonical;
  try {
    canonical = canonicalJson(manifest) === bytes.toString('utf8');
  } catch {
    canonical = false;
  }
  return { ok: true, manifest, canonical };
}

const MARKET = { '1x2': '1X2', ou25: 'Over/Under 2.5' };
const OUTCOME = {
  home: 'home win',
  draw: 'draw',
  away: 'away win',
  over: 'over 2.5',
  under: 'under 2.5',
};

/** One line per call: what was sealed. */
export function describeEntry(entry) {
  return {
    call: entry.call === 'pick' ? 'pick' : 'no pick',
    match: `${entry.home} v ${entry.away}`,
    market: MARKET[entry.market] ?? entry.market,
    outcome: OUTCOME[entry.outcome] ?? entry.outcome,
    probabilityPct: entry.probabilityPct,
    slug: entry.match,
  };
}
