import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { ENTRY_TYPE, verifySct } from '../src/index.js';
import { GOOGLE_PILOT_LOG, SYMANTEC_LOG } from './x509-google.fixtures.js';
import { readTestData } from '../scripts/utils.js';

describe('X.509 SCT verification with Google test data', () => {
  const cert = readTestData('google-cert.bin', 'x509');
  const logs = [GOOGLE_PILOT_LOG, SYMANTEC_LOG];
  const now = 1499619463644;

  test('verifies google-sct0.bin', () => {
    const sct = readTestData('google-sct0.bin', 'x509');
    const { log } = verifySct(sct, cert, ENTRY_TYPE.X509_ENTRY, now, logs);
    assert.deepStrictEqual(log, GOOGLE_PILOT_LOG);
  });

  test('verifies google-sct1.bin', () => {
    const sct = readTestData('google-sct1.bin', 'x509');
    const { log } = verifySct(sct, cert, ENTRY_TYPE.X509_ENTRY, now, logs);
    assert.deepStrictEqual(log, SYMANTEC_LOG);
  }); 
});
