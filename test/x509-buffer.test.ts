import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { KeyObject } from 'crypto';
import { ENTRY_TYPE, verifySct } from '../src/index.js';
import { Log } from '../src/types.js';
import * as generatedFixtures from './x509-generated.fixtures.js';
import * as googleFixtures from './x509-google.fixtures.js';
import { readTestData } from '../scripts/utils.js';

const CERT = Buffer.from('cert');
const NOW = 1235;

function createBufferTest(log: Log, sctFile: string) {
  // Export the KeyObject to a PEM buffer to test the buffer path
  const keyAsPem = (log.key as KeyObject).export({
    type: 'spki',
    format: 'pem',
  });

  const logWithBufferKey: Log = {
    ...log,
    key: Buffer.from(keyAsPem),
  };

  const result = verifySct(readTestData(sctFile, 'x509'), CERT, ENTRY_TYPE.X509_ENTRY, NOW, [logWithBufferKey]);
  assert.deepStrictEqual(result, logWithBufferKey);
}

describe('PEM Buffer Verification (Generated)', () => {
  test('ecdsa_p256', () => {
    createBufferTest(generatedFixtures.TEST_LOG_ECDSA_P256, 'ecdsa_p256-basic-sct.bin');
  });

  test('ecdsa_p384', () => {
    createBufferTest(generatedFixtures.TEST_LOG_ECDSA_P384, 'ecdsa_p384-basic-sct.bin');
  });

  test('rsa2048', () => {
    createBufferTest(generatedFixtures.TEST_LOG_RSA2048, 'rsa2048-basic-sct.bin');
  });

  test('rsa3072', () => {
    createBufferTest(generatedFixtures.TEST_LOG_RSA3072, 'rsa3072-basic-sct.bin');
  });

  test('rsa4096', () => {
    createBufferTest(generatedFixtures.TEST_LOG_RSA4096, 'rsa4096-basic-sct.bin');
  });
});

describe('PEM Buffer Verification (Google)', () => {
  const cert = readTestData('google-cert.bin', 'x509');
  const now = 1499619463644;

  function createGoogleBufferTest(log: Log, sctFile: string) {
    const keyAsPem = (log.key as KeyObject).export({
      type: 'spki',
      format: 'pem',
    });

    const logWithBufferKey: Log = {
      ...log,
      key: Buffer.from(keyAsPem),
    };

    const result = verifySct(readTestData(sctFile, 'x509'), cert, ENTRY_TYPE.X509_ENTRY, now, [logWithBufferKey]);
    assert.deepStrictEqual(result, logWithBufferKey);
  }

  test('google_pilot', () => {
    createGoogleBufferTest(googleFixtures.GOOGLE_PILOT_LOG, 'google-sct0.bin');
  });

  test('symantec', () => {
    createGoogleBufferTest(googleFixtures.SYMANTEC_LOG, 'google-sct1.bin');
  });
});
