import { KeyObject } from 'crypto';

/**
 * Describes a CT log.
 */
export interface Log {
  /**
   * The operator's name/description of the log.
   * This field is not used by the library.
   */
  description: string;

  /**
   * The certificate submission url.
   * This field is not used by the library.
   */
  url: string;

  /**
   * Which entity operates the log.
   * This field is not used by the library.
   */
  operated_by: string;

  /**
   * Public key usable for verifying certificates.
   * This is a DER-encoded SubjectPublicKeyInfo.
   */
  key: Buffer | KeyObject;

  /**
   * Key hash, which is SHA256 applied to the SPKI encoding.
   */
  id: Buffer;

  /**
   * The log's maximum merge delay.
   * This field is not used by the library.
   */
  max_merge_delay: number;
}

/**
 * How sct.js reports errors.
 */
export enum VerificationError {
  /**
   * The SCT was somehow misencoded, truncated or otherwise corrupt.
   */
  MalformedSct = 'MalformedSct',

  /**
   * The SCT contained an invalid signature.
   */
  InvalidSignature = 'InvalidSignature',

  /**
   * The SCT was signed in the future. Clock skew?
   */
  TimestampInFuture = 'TimestampInFuture',

  /**
   * The SCT had a version that this library does not handle.
   */
  UnsupportedSctVersion = 'UnsupportedSctVersion',

  /**
   * The SCT refers to an unknown log.
   */
  UnknownLog = 'UnknownLog',
}

/**
 * Checks if a verification error should be considered a fatal
 * failure according to a suggested policy.
 * @param err The error to check.
 * @returns `true` if processing should be aborted, `false` otherwise.
 */
export function shouldBeFatal(err: VerificationError): boolean {
  return err !== VerificationError.UnknownLog && err !== VerificationError.UnsupportedSctVersion;
}

/**
 * Represents a Signed Certificate Timestamp.
 */
export interface Sct {
  logId: Buffer;
  timestamp: bigint;
  signature: Buffer;
  extensions: Buffer;
  signatureAlgorithm: number;
}
