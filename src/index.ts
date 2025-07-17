export * from './constants.js';
export * from './types.js';

import { Log, Sct, VerificationError } from './types.js';
import { parseSct, verifySctSignature } from './verify.js';

function findLog(logs: Log[], sct: Sct): Log | undefined {
  return logs.find((log) => log.id.equals(sct.logId));
}

/**
 * Verifies a Signed Certificate Timestamp (SCT).
 *
 * @param cert DER-encoded X.509 end-entity certificate.
 * @param sct Raw `SignedCertificateTimestamp` structure.
 * @param atTime The time at which to verify the SCT (in ms since epoch).
 * @param logs A list of trusted CT logs.
 * @returns The log that issued the SCT.
 * @throws {VerificationError} If the SCT is invalid.
 */
export function verifySct(cert: Buffer, sct: Buffer, atTime: number, logs: Log[]): Log {
  const parsedSct = parseSct(sct);

  const log = findLog(logs, parsedSct);
  if (!log) {
    throw new Error(VerificationError.UnknownLog);
  }

  if (!verifySctSignature(parsedSct, log.key, cert)) {
    throw new Error(VerificationError.InvalidSignature);
  }

  if (parsedSct.timestamp > BigInt(atTime)) {
    throw new Error(VerificationError.TimestampInFuture);
  }

  return log;
}
