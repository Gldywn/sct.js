import { createHash, createPublicKey } from 'crypto';
import { readTestData } from '../scripts/utils.js';
import { Log } from '../src/index.js';

function createLog(logKeyFileName: string): Log {
  const publicKeyBuffer = readTestData(logKeyFileName, 'precert');
  const id = createHash('sha256').update(publicKeyBuffer).digest();
  const key = createPublicKey({ key: publicKeyBuffer, format: 'der', type: 'spki' });

  return {
    id,
    key,
    description: `Dynamically fetched log for ${logKeyFileName}`,
    url: 'test.com',
    operated_by: 'Test',
    max_merge_delay: 0,
    status: 'usable',
  };
}

export const sct0 = readTestData('google-sct0.bin', 'precert');
export const sct1 = readTestData('google-sct1.bin', 'precert');
export const precert = readTestData('google-precert.bin', 'precert');

export const log0 = createLog('log0-pubkey.bin');
export const log1 = createLog('log1-pubkey.bin');
