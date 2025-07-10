import { createVerify, KeyObject } from 'crypto';
import { BufferReader } from './util.js';
import { Sct, VerificationError } from './types.js';
import * as constants from './constants.js';

function getCryptoAlgorithm(sct: Sct): string | undefined {
  switch (sct.signatureAlgorithm) {
    case constants.SIGNATURE_ALGORITHMS.RSA_PKCS1_SHA256:
    case constants.SIGNATURE_ALGORITHMS.ECDSA_SHA256:
      return 'sha256';
    case constants.SIGNATURE_ALGORITHMS.RSA_PKCS1_SHA384:
    case constants.SIGNATURE_ALGORITHMS.ECDSA_SHA384:
      return 'sha384';
    default:
      return undefined;
  }
}

export function verifySctSignature(sct: Sct, logPublicKey: Buffer | KeyObject, certificate: Buffer): boolean {
  const algorithm = getCryptoAlgorithm(sct);
  if (!algorithm) {
    return false;
  }

  // Reconstruct the digitally signed data
  // https://tools.ietf.org/html/rfc6962#section-3.2

  // The timestamp is a 64-bit unsigned integer
  const timestampBuffer = Buffer.alloc(8);
  timestampBuffer.writeBigUInt64BE(sct.timestamp);

  // The certificate length is a 24-bit unsigned integer
  const certLengthBuffer = Buffer.alloc(3);
  certLengthBuffer.writeUIntBE(certificate.length, 0, 3);

  // The extensions length is a 16-bit unsigned integer
  const extLengthBuffer = Buffer.alloc(2);
  extLengthBuffer.writeUInt16BE(sct.extensions.length);

  const signedData = Buffer.concat([
    Buffer.from([constants.SCT_V1]),
    Buffer.from([constants.MERKLE_LEAF_TYPE.TIMESTAMPED_ENTRY]),
    timestampBuffer,
    Buffer.from(constants.LOG_ENTRY_TYPE.X509_ENTRY),
    certLengthBuffer,
    certificate,
    extLengthBuffer,
    sct.extensions,
  ]);

  const verifier = createVerify(algorithm);
  verifier.update(signedData);

  // The public key is passed in as-is. The `crypto` module will parse it.
  return verifier.verify(logPublicKey, sct.signature);
}

export function parseSct(buffer: Buffer): Sct {
  const reader = new BufferReader(buffer);

  // Check buffer length before parsing
  if (!reader.hasBytes(1)) {
    throw new Error(VerificationError.MalformedSct);
  }

  const version = reader.readUInt8();
  if (version !== constants.SCT_V1) {
    throw new Error(VerificationError.UnsupportedSctVersion);
  }

  if (!reader.hasBytes(32 + 8 + 2)) {
    throw new Error(VerificationError.MalformedSct);
  }

  const logId = reader.readBytes(32);
  const timestamp = reader.readBigUInt64BE();

  const extensionsLength = reader.readUInt16BE();
  if (!reader.hasBytes(extensionsLength)) {
    throw new Error(VerificationError.MalformedSct);
  }
  const extensions = reader.readBytes(extensionsLength);

  if (!reader.hasBytes(2 + 2)) {
    throw new Error(VerificationError.MalformedSct);
  }
  const signatureAlgorithm = reader.readUInt16BE();
  const signatureLength = reader.readUInt16BE();

  if (!reader.hasBytes(signatureLength)) {
    throw new Error(VerificationError.MalformedSct);
  }
  const signature = reader.readBytes(signatureLength);

  if (reader.remaining() > 0) {
    throw new Error(VerificationError.MalformedSct);
  }

  return {
    logId,
    timestamp,
    extensions,
    signatureAlgorithm,
    signature,
  };
}
