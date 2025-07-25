import { KeyObject } from 'crypto';

/**
 * Describes a CT log.
 */
type LogBase = {
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
};

export type Log =
  | (LogBase & {
      status: 'qualified' | 'usable' | 'readonly';
    })
  | (LogBase & {
      status: 'retired';
      retirement_date: number;
    });

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

  /**
   * The SCT was issued by a retired log after its retirement date.
   */
  SctFromRetiredLog = 'SctFromRetiredLog',
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
 * Custom error for SCT verification failures.
 * Encapsulates a machine-readable error code and a human-readable message.
 */
export class SctVerificationError extends Error {
  public readonly code: VerificationError;

  constructor(code: VerificationError, message: string) {
    super(message);
    this.name = 'SctVerificationError';
    this.code = code;
  }
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
