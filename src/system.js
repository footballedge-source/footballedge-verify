import process from 'node:process';
import { execFile } from 'node:child_process';
import { existsSync } from 'node:fs';
import { delimiter, join } from 'node:path';

/**
 * The outside world, behind one small interface so the tests can replace it:
 * finding and running `openssl` / `ots`, and the system's trusted root
 * certificates (DigiCert's root is in every common store).
 */

/** Full path of an executable on PATH, or null. */
export function which(command, env = process.env) {
  const exts = process.platform === 'win32' ? (env.PATHEXT ?? '.EXE;.CMD;.BAT').split(';') : [''];
  for (const dir of (env.PATH ?? '').split(delimiter)) {
    if (!dir) continue;
    for (const ext of exts) {
      const candidate = join(dir, command + ext);
      if (existsSync(candidate)) return candidate;
    }
  }
  return null;
}

/** Runs a command without a shell. Never throws: a failure is `code !== 0`. */
export function run(command, args, { timeoutMs = 60_000 } = {}) {
  return new Promise((resolve) => {
    execFile(
      command,
      args,
      { timeout: timeoutMs, maxBuffer: 4 * 1024 * 1024 },
      (error, stdout, stderr) => {
        const code = error ? (typeof error.code === 'number' ? error.code : 1) : 0;
        resolve({
          code,
          stdout: String(stdout ?? ''),
          stderr: String(stderr ?? '') || (error && !stderr ? String(error.message) : ''),
        });
      },
    );
  });
}

/** Where common systems keep their bundle of trusted root certificates. */
export const CA_BUNDLE_CANDIDATES = [
  '/etc/ssl/cert.pem', // macOS, Alpine, OpenBSD
  '/etc/ssl/certs/ca-certificates.crt', // Debian, Ubuntu, Arch
  '/etc/pki/tls/certs/ca-bundle.crt', // Fedora, RHEL
  '/etc/ssl/ca-bundle.pem', // openSUSE
  '/usr/local/etc/openssl/cert.pem', // Homebrew (older)
  '/opt/homebrew/etc/openssl@3/cert.pem', // Homebrew (Apple silicon)
  '/usr/local/etc/openssl@3/cert.pem', // Homebrew (Intel)
];

export function findCaBundle(exists = existsSync) {
  return CA_BUNDLE_CANDIDATES.find((path) => exists(path)) ?? null;
}

export const defaultSystem = {
  which,
  run,
  findCaBundle,
  fetch: (...args) => globalThis.fetch(...args),
};
