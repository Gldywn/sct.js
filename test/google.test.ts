import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { verifySct } from '../src/index.js';
import { GOOGLE_PILOT_LOG, SYMANTEC_LOG } from './google.fixtures.js';
import { readTestData } from './util.js';

describe('Google SCT tests', () => {
  const cert = readTestData('google-cert.bin');
  const logs = [GOOGLE_PILOT_LOG, SYMANTEC_LOG];
  const now = 1499619463644;

  test('verifies google-sct0.bin', () => {
    const sct = readTestData('google-sct0.bin');
    const result = verifySct(cert, sct, now, logs);
    assert.deepStrictEqual(result, GOOGLE_PILOT_LOG);
  });

  test('verifies google-sct1.bin', () => {
    const sct = readTestData('google-sct1.bin');
    const result = verifySct(cert, sct, now, logs);
    assert.deepStrictEqual(result, SYMANTEC_LOG);
  });
});
