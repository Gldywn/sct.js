import { createVerify, KeyObject } from 'crypto';
import { BufferReader } from './utils.js';
import { Sct, SctVerificationError, VerificationError } from './types.js';
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

/**
 * Verifies the signature of a Signed Certificate Timestamp (SCT).
 * @param sct The parsed SCT object.
 * @param signedEntry The entry that was signed (either a Precertificate or an X.509 certificate).
 * @param entryType The type of the `signedEntry`.
 * @param logPublicKey The public key of the log that issued the SCT.
 * @returns `true` if the signature is valid, `false` otherwise.
 */
export function verifySctSignature(
  sct: Sct,
  signedEntry: Buffer,
  entryType: (typeof constants.ENTRY_TYPE)[keyof typeof constants.ENTRY_TYPE],
  logPublicKey: Buffer | KeyObject
): boolean {
  const algorithm = getCryptoAlgorithm(sct);
  if (!algorithm) {
    return false;
  }
  // Reconstruct the digitally signed data
  // https://tools.ietf.org/html/rfc6962#section-3.2

  // The timestamp is a 64-bit unsigned integer
  const timestampBuffer = Buffer.alloc(8);
  timestampBuffer.writeBigUInt64BE(sct.timestamp);

  // The extensions length is a 16-bit unsigned integer
  const extLengthBuffer = Buffer.alloc(2);
  extLengthBuffer.writeUInt16BE(sct.extensions.length);

  const signedData = Buffer.concat([
    Buffer.from([constants.SCT_V1]),
    Buffer.from([constants.MERKLE_LEAF_TYPE.TIMESTAMPED_ENTRY]),
    timestampBuffer,
    Buffer.from(entryType),
    entryType === constants.ENTRY_TYPE.X509_ENTRY
      ? (() => {
          const certLengthBuffer = Buffer.alloc(3);
          certLengthBuffer.writeUIntBE(signedEntry.length, 0, 3);
          return Buffer.concat([certLengthBuffer, signedEntry]);
        })()
      : signedEntry, // For precert_entry, the length is part of the PreCert structure
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
    throw new SctVerificationError(
      VerificationError.MalformedSct,
      'SCT is too short to contain a version number',
    );
  }

  const version = reader.readUInt8();

  if (version !== constants.SCT_V1) {
    throw new SctVerificationError(
      VerificationError.UnsupportedSctVersion,
      `Unsupported SCT version: ${version}`,
    );
  }

  const MIN_V1_SCT_LENGTH = 32 + 8 + 2;
  if (!reader.hasBytes(MIN_V1_SCT_LENGTH)) {
    throw new SctVerificationError(
      VerificationError.MalformedSct,
      `SCT is too short to contain V1 header fields`,
    );
  }

  const logId = reader.readBytes(32);
  const timestamp = reader.readBigUInt64BE();

  const extensionsLength = reader.readUInt16BE();
  if (!reader.hasBytes(extensionsLength)) {
    throw new SctVerificationError(
      VerificationError.MalformedSct,
      `SCT is too short to contain extensions (expected ${extensionsLength} bytes, got ${reader.remaining()})`,
    );
  }
  const extensions = reader.readBytes(extensionsLength);

  const MIN_TRAILER_LENGTH = 2 + 2;
  if (!reader.hasBytes(MIN_TRAILER_LENGTH)) {
    throw new SctVerificationError(
      VerificationError.MalformedSct,
      `SCT is too short to contain signature algorithm and length`,
    );
  }
  const signatureAlgorithm = reader.readUInt16BE();
  const signatureLength = reader.readUInt16BE();

  if (!reader.hasBytes(signatureLength)) {
    throw new SctVerificationError(
      VerificationError.MalformedSct,
      `SCT is too short to contain signature (expected ${signatureLength} bytes, got ${reader.remaining()})`,
    );
  }
  const signature = reader.readBytes(signatureLength);

  if (reader.remaining() > 0) {
    throw new SctVerificationError(
      VerificationError.MalformedSct,
      `SCT has trailing data (${reader.remaining()} bytes)`,
    );
  }

  return {
    logId,
    timestamp,
    extensions,
    signatureAlgorithm,
    signature,
  };
}
