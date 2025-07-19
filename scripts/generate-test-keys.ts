import { writeFileSync, mkdirSync, existsSync } from 'fs';
import { join } from 'path';
import { generateKeyPairSync } from 'crypto';
import { getTestDataDir } from './utils.js';

const PRECERT_TESTDATA_DIR = getTestDataDir('precert');
const PRECERT_TESTDATA_KEYS_DIR = join(PRECERT_TESTDATA_DIR, 'keys');

function generateKeys(algorithm: 'ecdsa-p256' | 'ecdsa-p384' | 'rsa-2048' | 'rsa-3072' | 'rsa-4096') {
  let keyPair;

  if (algorithm.startsWith('ec')) {
    let namedCurve: string;
    if (algorithm === 'ecdsa-p256') {
      namedCurve = 'prime256v1';
    } else {
      namedCurve = 'secp384r1';
    }
    keyPair = generateKeyPairSync('ec', {
      namedCurve,
    });
  } else {
    let modulusLength: number;
    if (algorithm === 'rsa-2048') {
      modulusLength = 2048;
    } else if (algorithm === 'rsa-3072') {
      modulusLength = 3072;
    } else {
      modulusLength = 4096;
    }
    keyPair = generateKeyPairSync('rsa', {
      modulusLength,
      publicExponent: 0x10001,
    });
  }

  if (!existsSync(PRECERT_TESTDATA_KEYS_DIR)) {
    mkdirSync(PRECERT_TESTDATA_KEYS_DIR, { recursive: true });
  }

  const privateKeyPem = keyPair.privateKey.export({
    type: algorithm.startsWith('ec') ? 'sec1' : 'pkcs8',
    format: 'pem',
  });
  writeFileSync(join(PRECERT_TESTDATA_KEYS_DIR, `${algorithm}-private.pem`), privateKeyPem);

  const publicKeyDer = keyPair.publicKey.export({ type: 'spki', format: 'der' });
  writeFileSync(join(PRECERT_TESTDATA_KEYS_DIR, `${algorithm}-public.der`), publicKeyDer);

  console.log(`Generated and saved ${algorithm} keys.`);
}

function main() {
  const algs = ['ecdsa-p256', 'ecdsa-p384', 'rsa-2048', 'rsa-3072', 'rsa-4096'];
  for (const alg of algs) {
    generateKeys(alg as any);
  }
  console.log('Precert test keys generation complete.');
}

main();
