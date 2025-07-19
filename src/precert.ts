import { createHash } from 'crypto';
import { Certificate } from 'pkijs';
import { SCT_EXTENSION_OID_V1 } from './constants.js';

/**
 * Reconstructs the Precertificate "signed_entry" structure to be used for SCT signature verification.
 * @param leafCert DER-encoded leaf cert (Buffer)
 * @param issuerCert DER-encoded issuer cert (Buffer)
 * @returns Buffer of the "signed_entry" for precert verification
 */
export function reconstructPrecert(leafCert: Buffer, issuerCert: Buffer): Buffer {
  const leaf = Certificate.fromBER(leafCert);
  const issuer = Certificate.fromBER(issuerCert);

  // Find and remove the SCT extension
  leaf.extensions = leaf.extensions?.filter((ext) => ext.extnID !== SCT_EXTENSION_OID_V1);

  // Re-encode the TBS part of the certificate
  const tbsBuffer = Buffer.from(leaf.encodeTBS().toBER());

  // Compute issuer key hash
  const issuerSpkiBuffer = Buffer.from(issuer.subjectPublicKeyInfo.toSchema().toBER());
  const issuerKeyHash = createHash('sha256').update(issuerSpkiBuffer).digest();

  // The PreCert entry structure requires a 3-byte length prefix for the TBS data
  const tbsLength = Buffer.alloc(3);
  tbsLength.writeUIntBE(tbsBuffer.length, 0, 3);

  return Buffer.concat([issuerKeyHash, tbsLength, tbsBuffer]);
}
