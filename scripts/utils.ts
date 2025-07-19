import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { readFileSync } from 'fs';
import { createPublicKey, KeyObject } from 'crypto';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

export function getScriptDir(): string {
  return __dirname;
}

export function getTestDataDir(testType: 'precert' | 'x509'): string {
  return join(__dirname, '..', 'test', `${testType}-testdata`);
}

export function readTestData(fileName: string, testType: 'precert' | 'x509'): Buffer {
  return readFileSync(join(getTestDataDir(testType), fileName));
}

export function getPrecertKeys(alg: string): { privateKey: string; publicKey: Buffer } {
  const keysDir = join(getTestDataDir('precert'), 'keys');
  const privateKey = readFileSync(join(keysDir, `${alg}-private.pem`), 'utf-8');
  const publicKey = readFileSync(join(keysDir, `${alg}-public.der`));
  return { privateKey, publicKey };
}

/**
 * Converts a raw uncompressed ECDSA public key to a crypto.KeyObject.
 * The key is expected to be in the format 0x04 || x-coordinate || y-coordinate.
 * @param rawPublicKey The raw public key.
 * @returns A KeyObject for the public key.
 */
export function jwkFromRawEcdsa(rawPublicKey: Buffer): KeyObject {
  // Determine curve from key length
  let crv: string;
  let keyLen: number;
  if (rawPublicKey.length === 65) {
    crv = 'P-256';
    keyLen = 32;
  } else if (rawPublicKey.length === 97) {
    crv = 'P-384';
    keyLen = 48;
  } else {
    throw new Error('Unknown curve for raw public key');
  }

  // Raw key is 65/97 bytes: 0x04 (uncompressed) + X-coord + Y-coord
  const x = rawPublicKey.subarray(1, 1 + keyLen);
  const y = rawPublicKey.subarray(1 + keyLen, 1 + 2 * keyLen);

  const jwk = { kty: 'EC', crv, x: x.toString('base64url'), y: y.toString('base64url') };
  return createPublicKey({ key: jwk, format: 'jwk' });
}

/**
 * Converts a raw uncompressed P-256 public key to a crypto.KeyObject.
 * The key is expected to be 65 bytes: 0x04 || 32-byte x-coordinate || 32-byte y-coordinate.
 * @param rawPublicKey The raw P-256 public key.
 * @returns A KeyObject for the public key.
 */
export function jwkFromRawP256(rawPublicKey: Buffer): KeyObject {
  // Raw key is 65 bytes: 0x04 (uncompressed) + 32-byte X + 32-byte Y
  const x = rawPublicKey.subarray(1, 33);
  const y = rawPublicKey.subarray(33, 65);

  const jwk = {
    kty: 'EC',
    crv: 'P-256',
    x: x.toString('base64url'),
    y: y.toString('base64url'),
  };

  return createPublicKey({ key: jwk, format: 'jwk' });
}
