import { writeFileSync, mkdirSync, existsSync } from 'fs';
import { join } from 'path';
import { createSign, createHash, randomBytes } from 'crypto';
import { reconstructPrecert, Sct, ENTRY_TYPE } from '../src/index.js';
import * as constants from '../src/constants.js';
import { getTestDataDir, readTestData, getPrecertKeys } from './utils.js';

const PRECERT_TESTDATA_DIR = getTestDataDir('precert');

const LEAF_CERT = readTestData('leaf_google-cert.bin', 'precert');
const ISSUER_CERT = readTestData('issuer_google-cert.bin', 'precert');

function createPrecertSignedData(precert: Buffer, timestamp: bigint, extensions: Buffer): Buffer {
  const timestampBuffer = Buffer.alloc(8);
  timestampBuffer.writeBigUInt64BE(timestamp);

  const extLengthBuffer = Buffer.alloc(2);
  extLengthBuffer.writeUInt16BE(extensions.length);

  return Buffer.concat([
    Buffer.from([constants.SCT_V1]),
    Buffer.from([constants.MERKLE_LEAF_TYPE.TIMESTAMPED_ENTRY]),
    timestampBuffer,
    Buffer.from(ENTRY_TYPE.PRECERT_ENTRY),
    precert,
    extLengthBuffer,
    extensions,
  ]);
}

function serializeSct(sct: Sct): Buffer {
  if (sct.logId.length !== 32) {
    throw new Error('logId must be exactly 32 bytes');
  }

  const versionBuffer = Buffer.from([constants.SCT_V1]);

  const timestampBuffer = Buffer.alloc(8);
  timestampBuffer.writeBigUInt64BE(sct.timestamp);

  const extensions = Buffer.isBuffer(sct.extensions) ? sct.extensions : Buffer.from(sct.extensions);
  const extensionsLengthBuffer = Buffer.alloc(2);
  extensionsLengthBuffer.writeUInt16BE(extensions.length);

  const signatureAlgorithmBuffer = Buffer.alloc(2);
  signatureAlgorithmBuffer.writeUInt16BE(sct.signatureAlgorithm);

  const signature = Buffer.isBuffer(sct.signature) ? sct.signature : Buffer.from(sct.signature);
  const signatureLengthBuffer = Buffer.alloc(2);
  signatureLengthBuffer.writeUInt16BE(signature.length);

  return Buffer.concat([
    versionBuffer,
    sct.logId,
    timestampBuffer,
    extensionsLengthBuffer,
    extensions,
    signatureAlgorithmBuffer,
    signatureLengthBuffer,
    signature,
  ]);
}

const SIGNATURE_ALGORITHMS_MAP: Record<string, number> = {
  'ecdsa-p256': constants.SIGNATURE_ALGORITHMS.ECDSA_SHA256,
  'ecdsa-p384': constants.SIGNATURE_ALGORITHMS.ECDSA_SHA384,
  'rsa-2048': constants.SIGNATURE_ALGORITHMS.RSA_PKCS1_SHA256,
  'rsa-3072': constants.SIGNATURE_ALGORITHMS.RSA_PKCS1_SHA256,
  'rsa-4096': constants.SIGNATURE_ALGORITHMS.RSA_PKCS1_SHA256,
};

async function generateForAlgorithm(alg: string, precert: Buffer) {
  const { privateKey, publicKey } = getPrecertKeys(alg);

  const logId = createHash('sha256').update(publicKey).digest();

  const now = BigInt(Date.now());
  const extensions = Buffer.from([]);

  const signedData = createPrecertSignedData(precert, now, extensions);

  const hashAlgorithm = alg === 'ecdsa-p384' ? 'sha384' : 'sha256';
  const signer = createSign(hashAlgorithm);
  signer.update(signedData);
  const signature = signer.sign(privateKey);

  const baseSct: Sct = {
    logId: logId,
    timestamp: now,
    extensions: extensions,
    signatureAlgorithm: SIGNATURE_ALGORITHMS_MAP[alg],
    signature: signature,
  };

  // Valid SCT
  const validSctBuffer = serializeSct(baseSct);
  writeFileSync(join(PRECERT_TESTDATA_DIR, `${alg}_sct-valid.bin`), validSctBuffer);

  // SCT with future timestamp
  const futureTimestamp = now + BigInt(24 * 60 * 60 * 1000);
  const futureSignedData = createPrecertSignedData(precert, futureTimestamp, extensions);
  const futureSigner = createSign(hashAlgorithm);
  futureSigner.update(futureSignedData);
  const futureSignature = futureSigner.sign(privateKey);
  const futureSct = { ...baseSct, timestamp: futureTimestamp, signature: futureSignature };
  const futureSctBuffer = serializeSct(futureSct);
  writeFileSync(join(PRECERT_TESTDATA_DIR, `${alg}_sct-future.bin`), futureSctBuffer);

  // SCT with bad signature
  const badSignature = Buffer.from(signature);
  badSignature[badSignature.length - 1] ^= 0xff;
  const badSigSct = { ...baseSct, signature: badSignature };
  const badSigSctBuffer = serializeSct(badSigSct);
  writeFileSync(join(PRECERT_TESTDATA_DIR, `${alg}_sct-badsig.bin`), badSigSctBuffer);

  // SCT with wrong log ID
  const wrongLogId = randomBytes(32);
  const wrongIdSct = { ...baseSct, logId: wrongLogId };
  const wrongIdSctBuffer = serializeSct(wrongIdSct);
  writeFileSync(join(PRECERT_TESTDATA_DIR, `${alg}_sct-wrongid.bin`), wrongIdSctBuffer);

  console.log(`Generated test data for ${alg}.`);
}

async function main() {
  if (!existsSync(PRECERT_TESTDATA_DIR)) {
    mkdirSync(PRECERT_TESTDATA_DIR, { recursive: true });
  }

  const precert = reconstructPrecert(LEAF_CERT, ISSUER_CERT);
  writeFileSync(join(PRECERT_TESTDATA_DIR, 'google-precert.bin'), precert);

  const algs = ['ecdsa-p256', 'ecdsa-p384', 'rsa-2048', 'rsa-3072', 'rsa-4096'];
  for (const alg of algs) {
    await generateForAlgorithm(alg, precert);
  }

  console.log('Precert test data generation complete.');
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
