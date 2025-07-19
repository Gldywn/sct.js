import { createHash, createPublicKey } from 'crypto';
import { readTestData, getPrecertKeys } from '../scripts/utils.js';
import { Log } from '../src/index.js';

const ALGORITHMS = ['ecdsa-p256', 'ecdsa-p384', 'rsa-2048', 'rsa-3072', 'rsa-4096'];

export const precert = readTestData('google-precert.bin', 'precert');

export const logs: Record<string, Log> = {};
export const scts: Record<string, Record<string, Buffer>> = {};

for (const alg of ALGORITHMS) {
    const publicKeyBuffer = getPrecertKeys(alg).publicKey;
    const logId = createHash('sha256').update(publicKeyBuffer).digest();
    
    logs[alg] = {
        id: logId,
        key: createPublicKey({ key: publicKeyBuffer, format: 'der', type: 'spki' }),
        description: `${alg} Test Log`,
        url: 'test.com',
        operated_by: 'Test',
        max_merge_delay: 0,
    };

    scts[alg] = {
        valid: readTestData(`${alg}_sct-valid.bin`, 'precert'),
        future: readTestData(`${alg}_sct-future.bin`, 'precert'),
        badsig: readTestData(`${alg}_sct-badsig.bin`, 'precert'),
        wrongid: readTestData(`${alg}_sct-wrongid.bin`, 'precert'),
    };
}