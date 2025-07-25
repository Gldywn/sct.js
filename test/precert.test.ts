import { describe, it } from 'node:test';
import { deepStrictEqual } from 'node:assert';
import { readFileSync, writeFileSync } from 'node:fs';
import { reconstructPrecert } from '../src/index.js';
import { readTestData } from '../scripts/utils.js';

const SNAPSHOT_PATH = './test/precert.test.ts.snapshot';

describe('Reconstructing a pre-certificate', () => {
  it('should correctly reconstruct the precertificate structure', () => {
    const leafCert = readTestData('leaf_google-cert.bin', 'precert');
    const issuerCert = readTestData('issuer_google-cert.bin', 'precert');

    const result = reconstructPrecert(leafCert, issuerCert);

    let snapshot: Buffer;
    try {
      // If the snapshot file exists, read it and compare from it
      snapshot = readFileSync(SNAPSHOT_PATH);
    } catch (e) {
      writeFileSync(SNAPSHOT_PATH, result);
      snapshot = result;
    }

    deepStrictEqual(result, snapshot, 'The reconstructed precert should match the snapshot.');
  });
});
