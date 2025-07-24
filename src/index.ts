export * from './constants.js';
export * from './types.js';

export { reconstructPrecert } from './precert.js';

import { Log, SctVerificationError, VerificationError } from './types.js';
import { ENTRY_TYPE } from './constants.js';
import { Sct } from './types.js';
import { parseSct, verifySctSignature } from './verify.js';

function findLog(logs: Log[], sct: Sct): Log | undefined {
  return logs.find((log) => log.id.equals(sct.logId));
}

/**
 * Verifies a Signed Certificate Timestamp (SCT).
 *
 * @example
 * ```
 * // For an X.509 certificate
 * verifySct(sctBuffer, certBuffer, ENTRY_TYPE.X509_ENTRY, Date.now(), trustedLogs);
 *
 * // For a pre-certificate
 * const precert = reconstructPrecert(leafCert, issuerCert);
 * verifySct(sctBuffer, precertBuffer, ENTRY_TYPE.PRECERT_ENTRY, Date.now(), trustedLogs);
 * ```
 *
 * @param sct Raw `SignedCertificateTimestamp` structure.
 * @param signedEntry The entry to be verified. This can be either a DER-encoded X.509 certificate (`x509_entry`) or a reconstructed Precertificate (`precert_entry`).
 * @param entryType The type of the `signedEntry` (`x509_entry` or `precert_entry`).
 * @param atTime The time at which to verify the SCT (in ms since epoch).
 * @param logs A list of trusted CT logs.
 * @returns The log that issued the SCT.
 * @throws {VerificationError} If the SCT is invalid.
 */
export function verifySct(
  sct: Buffer,
  signedEntry: Buffer,
  entryType: (typeof ENTRY_TYPE)[keyof typeof ENTRY_TYPE],
  atTime: number,
  logs: Log[],
): Log {
  const parsedSct = parseSct(sct);

  const log = findLog(logs, parsedSct);
  if (!log) {
    const logId = parsedSct.logId.toString('hex');
    throw new SctVerificationError(
      VerificationError.UnknownLog,
      `Log ID ${logId} not found in trusted logs`,
    );
  }

  if (!verifySctSignature(parsedSct, signedEntry, entryType, log.key)) {
    const logId = parsedSct.logId.toString('hex');
    throw new SctVerificationError(
      VerificationError.InvalidSignature,
      `Invalid SCT signature from log ${logId}`,
    );
  }

  if (parsedSct.timestamp > BigInt(atTime)) {
    const sctDate = new Date(Number(parsedSct.timestamp));
    const verificationDate = new Date(atTime);
    throw new SctVerificationError(
      VerificationError.TimestampInFuture,
      `SCT timestamp (${sctDate.toISOString()}) is in the future (verification time: ${verificationDate.toISOString()})`,
    );
  }

  return log;
}
