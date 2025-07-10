import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { verifySct } from '../src/index.js';
import { VerificationError } from '../src/types.js';
import * as fixtures from './generated.fixtures.js';
import { readTestData } from './util.js';

const CERT = Buffer.from('cert');
const NOW = 1235;

describe('Generated SCT tests', () => {
  // ECDSA P-256
  describe('ecdsa_p256', () => {
    const logs = [fixtures.TEST_LOG_ECDSA_P256];
    test('basic', () => {
      const sct = readTestData('ecdsa_p256-basic-sct.bin');
      const result = verifySct(CERT, sct, NOW, logs);
      assert.deepStrictEqual(result, fixtures.TEST_LOG_ECDSA_P256);
    });

    test('wrongtime', () => {
      const sct = readTestData('ecdsa_p256-wrongtime-sct.bin');
      assert.throws(() => verifySct(CERT, sct, NOW, logs), new Error(VerificationError.InvalidSignature));
    });

    test('wrongcert', () => {
      const sct = readTestData('ecdsa_p256-wrongcert-sct.bin');
      assert.throws(() => verifySct(CERT, sct, NOW, logs), new Error(VerificationError.InvalidSignature));
    });
  });

  // ECDSA P-384
  describe('ecdsa_p384', () => {
    const logs = [fixtures.TEST_LOG_ECDSA_P384];
    test('basic', () => {
      const sct = readTestData('ecdsa_p384-basic-sct.bin');
      const result = verifySct(CERT, sct, NOW, logs);
      assert.deepStrictEqual(result, fixtures.TEST_LOG_ECDSA_P384);
    });

    test('wrongtime', () => {
      const sct = readTestData('ecdsa_p384-wrongtime-sct.bin');
      assert.throws(() => verifySct(CERT, sct, NOW, logs), new Error(VerificationError.InvalidSignature));
    });

    test('wrongcert', () => {
      const sct = readTestData('ecdsa_p384-wrongcert-sct.bin');
      assert.throws(() => verifySct(CERT, sct, NOW, logs), new Error(VerificationError.InvalidSignature));
    });
  });

  // RSA 2048
  describe('rsa2048', () => {
    const logs = [fixtures.TEST_LOG_RSA2048];
    test('basic', () => {
      const sct = readTestData('rsa2048-basic-sct.bin');
      const result = verifySct(CERT, sct, NOW, logs);
      assert.deepStrictEqual(result, fixtures.TEST_LOG_RSA2048);
    });

    test('wrongtime', () => {
      const sct = readTestData('rsa2048-wrongtime-sct.bin');
      assert.throws(() => verifySct(CERT, sct, NOW, logs), new Error(VerificationError.InvalidSignature));
    });

    test('wrongcert', () => {
      const sct = readTestData('rsa2048-wrongcert-sct.bin');
      assert.throws(() => verifySct(CERT, sct, NOW, logs), new Error(VerificationError.InvalidSignature));
    });
  });

  // RSA 3072
  describe('rsa3072', () => {
    const logs = [fixtures.TEST_LOG_RSA3072];
    test('basic', () => {
      const sct = readTestData('rsa3072-basic-sct.bin');
      const result = verifySct(CERT, sct, NOW, logs);
      assert.deepStrictEqual(result, fixtures.TEST_LOG_RSA3072);
    });

    test('wrongtime', () => {
      const sct = readTestData('rsa3072-wrongtime-sct.bin');
      assert.throws(() => verifySct(CERT, sct, NOW, logs), new Error(VerificationError.InvalidSignature));
    });

    test('wrongcert', () => {
      const sct = readTestData('rsa3072-wrongcert-sct.bin');
      assert.throws(() => verifySct(CERT, sct, NOW, logs), new Error(VerificationError.InvalidSignature));
    });
  });

  // RSA 4096
  describe('rsa4096', () => {
    const logs = [fixtures.TEST_LOG_RSA4096];
    test('basic', () => {
      const sct = readTestData('rsa4096-basic-sct.bin');
      const result = verifySct(CERT, sct, NOW, logs);
      assert.deepStrictEqual(result, fixtures.TEST_LOG_RSA4096);
    });

    test('wrongtime', () => {
      const sct = readTestData('rsa4096-wrongtime-sct.bin');
      assert.throws(() => verifySct(CERT, sct, NOW, logs), new Error(VerificationError.InvalidSignature));
    });

    test('wrongcert', () => {
      const sct = readTestData('rsa4096-wrongcert-sct.bin');
      assert.throws(() => verifySct(CERT, sct, NOW, logs), new Error(VerificationError.InvalidSignature));
    });
  });

  // Other failure cases (using ecdsa_p256)
  describe('other failures', () => {
    const logs = [fixtures.TEST_LOG_ECDSA_P256];
    test('junk', () => {
      const sct = readTestData('ecdsa_p256-junk-sct.bin');
      assert.throws(() => verifySct(CERT, sct, NOW, logs), new Error(VerificationError.MalformedSct));
    });

    test('wrongid', () => {
      const sct = readTestData('ecdsa_p256-wrongid-sct.bin');
      assert.throws(() => verifySct(CERT, sct, NOW, logs), new Error(VerificationError.UnknownLog));
    });

    test('version', () => {
      const sct = readTestData('ecdsa_p256-version-sct.bin');
      assert.throws(() => verifySct(CERT, sct, NOW, logs), new Error(VerificationError.UnsupportedSctVersion));
    });

    test('future', () => {
      const sct = readTestData('ecdsa_p256-future-sct.bin');
      assert.throws(() => verifySct(CERT, sct, 1233, logs), new Error(VerificationError.TimestampInFuture));
    });

    test('wrongext', () => {
      const sct = readTestData('ecdsa_p256-wrongext-sct.bin');
      assert.throws(() => verifySct(CERT, sct, NOW, logs), new Error(VerificationError.InvalidSignature));
    });

    test('badsigalg', () => {
      const sct = readTestData('ecdsa_p256-badsigalg-sct.bin');
      assert.throws(() => verifySct(CERT, sct, NOW, logs), new Error(VerificationError.InvalidSignature));
    });

    test('short', () => {
      const sct = readTestData('ecdsa_p256-short-sct.bin');
      for (let i = 0; i < sct.length; i++) {
        const truncatedSct = sct.subarray(0, i);
        assert.throws(() => verifySct(CERT, truncatedSct, 1234, logs), new Error(VerificationError.MalformedSct));
      }
    });
  });
});
