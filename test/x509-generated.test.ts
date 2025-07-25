import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { ENTRY_TYPE, verifySct } from '../src/index.js';
import { VerificationError } from '../src/types.js';
import * as fixtures from './x509-generated.fixtures.js';
import { readTestData } from '../scripts/utils.js';

const CERT = Buffer.from('cert');
const NOW = 1235;

describe('X.509 SCT verification with generated data', () => {
  // ECDSA P-256
  describe('When using ecdsa_p256', () => {
    const logs = [fixtures.TEST_LOG_ECDSA_P256];
    
    test('basic', () => {
      const sct = readTestData('ecdsa_p256-basic-sct.bin', 'x509');
      const { log } = verifySct(sct, CERT, ENTRY_TYPE.X509_ENTRY, NOW, logs);
      assert.deepStrictEqual(log, fixtures.TEST_LOG_ECDSA_P256);
    });

    test('wrongtime', () => {
      const sct = readTestData('ecdsa_p256-wrongtime-sct.bin', 'x509');
      assert.throws(() => verifySct(sct, CERT, ENTRY_TYPE.X509_ENTRY, NOW, logs), { code: VerificationError.InvalidSignature });
    });

    test('wrongcert', () => {
      const sct = readTestData('ecdsa_p256-wrongcert-sct.bin', 'x509');
      assert.throws(() => verifySct(sct, CERT, ENTRY_TYPE.X509_ENTRY, NOW, logs), { code: VerificationError.InvalidSignature });
    });
  });

  // ECDSA P-384
  describe('When using ecdsa_p384', () => {
    const logs = [fixtures.TEST_LOG_ECDSA_P384];
    
    test('basic', () => {
      const sct = readTestData('ecdsa_p384-basic-sct.bin', 'x509');
      const { log } = verifySct(sct, CERT, ENTRY_TYPE.X509_ENTRY, NOW, logs);
      assert.deepStrictEqual(log, fixtures.TEST_LOG_ECDSA_P384);
    });

    test('wrongtime', () => {
      const sct = readTestData('ecdsa_p384-wrongtime-sct.bin', 'x509');
      assert.throws(() => verifySct(sct, CERT, ENTRY_TYPE.X509_ENTRY, NOW, logs), { code: VerificationError.InvalidSignature });
    });

    test('wrongcert', () => {
      const sct = readTestData('ecdsa_p384-wrongcert-sct.bin', 'x509');
      assert.throws(() => verifySct(sct, CERT, ENTRY_TYPE.X509_ENTRY, NOW, logs), { code: VerificationError.InvalidSignature });
    });
  });

  // RSA 2048
  describe('When using rsa2048', () => {
    const logs = [fixtures.TEST_LOG_RSA2048];
    
    test('basic', () => {
      const sct = readTestData('rsa2048-basic-sct.bin', 'x509');
      const { log } = verifySct(sct, CERT, ENTRY_TYPE.X509_ENTRY, NOW, logs);
      assert.deepStrictEqual(log, fixtures.TEST_LOG_RSA2048);
    });

    test('wrongtime', () => {
      const sct = readTestData('rsa2048-wrongtime-sct.bin', 'x509');
      assert.throws(() => verifySct(sct, CERT, ENTRY_TYPE.X509_ENTRY, NOW, logs), { code: VerificationError.InvalidSignature });
    });

    test('wrongcert', () => {
      const sct = readTestData('rsa2048-wrongcert-sct.bin', 'x509');
      assert.throws(() => verifySct(sct, CERT, ENTRY_TYPE.X509_ENTRY, NOW, logs), { code: VerificationError.InvalidSignature });
    });
  });

  // RSA 3072
  describe('When using rsa3072', () => {
    const logs = [fixtures.TEST_LOG_RSA3072];
    
    test('basic', () => {
      const sct = readTestData('rsa3072-basic-sct.bin', 'x509');
      const { log } = verifySct(sct, CERT, ENTRY_TYPE.X509_ENTRY, NOW, logs);
      assert.deepStrictEqual(log, fixtures.TEST_LOG_RSA3072);
    });

    test('wrongtime', () => {
      const sct = readTestData('rsa3072-wrongtime-sct.bin', 'x509');
      assert.throws(() => verifySct(sct, CERT, ENTRY_TYPE.X509_ENTRY, NOW, logs), { code: VerificationError.InvalidSignature });
    });

    test('wrongcert', () => {
      const sct = readTestData('rsa3072-wrongcert-sct.bin', 'x509');
        assert.throws(() => verifySct(sct, CERT, ENTRY_TYPE.X509_ENTRY, NOW, logs), { code: VerificationError.InvalidSignature });
    });
  });

  // RSA 4096
  describe('When using rsa4096', () => {
    const logs = [fixtures.TEST_LOG_RSA4096];
    
    test('basic', () => {
      const sct = readTestData('rsa4096-basic-sct.bin', 'x509');
      const { log } = verifySct(sct, CERT, ENTRY_TYPE.X509_ENTRY, NOW, logs);
      assert.deepStrictEqual(log, fixtures.TEST_LOG_RSA4096);
    });

    test('wrongtime', () => {
      const sct = readTestData('rsa4096-wrongtime-sct.bin', 'x509');
      assert.throws(() => verifySct(sct, CERT, ENTRY_TYPE.X509_ENTRY, NOW, logs), { code: VerificationError.InvalidSignature });
    });

    test('wrongcert', () => {
      const sct = readTestData('rsa4096-wrongcert-sct.bin', 'x509');
      assert.throws(() => verifySct(sct, CERT, ENTRY_TYPE.X509_ENTRY, NOW, logs), { code: VerificationError.InvalidSignature });
    });
  });

  // Other failure cases (using ecdsa_p256)
  describe('When handling other failure cases', () => {
    const logs = [fixtures.TEST_LOG_ECDSA_P256];
    
    test('junk', () => {
      const sct = readTestData('ecdsa_p256-junk-sct.bin', 'x509');
      assert.throws(() => verifySct(sct, CERT, ENTRY_TYPE.X509_ENTRY, NOW, logs), { code: VerificationError.MalformedSct });
    });

    test('wrongid', () => {
      const sct = readTestData('ecdsa_p256-wrongid-sct.bin', 'x509');
      assert.throws(() => verifySct(sct, CERT, ENTRY_TYPE.X509_ENTRY, NOW, logs), { code: VerificationError.UnknownLog });
    });

    test('version', () => {
      const sct = readTestData('ecdsa_p256-version-sct.bin', 'x509');
      assert.throws(() => verifySct(sct, CERT, ENTRY_TYPE.X509_ENTRY, NOW, logs), { code: VerificationError.UnsupportedSctVersion });
    });

    test('future', () => {
      const sct = readTestData('ecdsa_p256-future-sct.bin', 'x509');
      assert.throws(() => verifySct(sct, CERT, ENTRY_TYPE.X509_ENTRY, 1233, logs), { code: VerificationError.TimestampInFuture });
    });

    test('wrongext', () => {
      const sct = readTestData('ecdsa_p256-wrongext-sct.bin', 'x509');
      assert.throws(() => verifySct(sct, CERT, ENTRY_TYPE.X509_ENTRY, NOW, logs), { code: VerificationError.InvalidSignature });
    });

    test('badsigalg', () => {
      const sct = readTestData('ecdsa_p256-badsigalg-sct.bin', 'x509');
      assert.throws(() => verifySct(sct, CERT, ENTRY_TYPE.X509_ENTRY, NOW, logs), { code: VerificationError.InvalidSignature });
    });

    test('short', () => {
      const sct = readTestData('ecdsa_p256-short-sct.bin', 'x509');
      for (let i = 0; i < sct.length; i++) {
        const truncatedSct = sct.subarray(0, i);
        assert.throws(() => verifySct(truncatedSct, CERT, ENTRY_TYPE.X509_ENTRY, 1234, logs), { code: VerificationError.MalformedSct });
      }
    });
  });
});
