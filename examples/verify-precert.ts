import { createPublicKey, createHash } from 'crypto';
import { verifySct, reconstructPrecert, ENTRY_TYPE, Log } from '../src/index.js';
import { readTestData } from '../scripts/utils.js';

try {
  // The leaf certificate (end-entity) and the issuer certificate both DER-encoded X.509
  const leafCert = readTestData('leaf_google-cert.bin', 'precert');
  const issuerCert = readTestData('issuer_google-cert.bin', 'precert');

  // The SCT embedded within the leaf certificate (extracted from the certificate itself)
  const precertSct = readTestData('google-sct0.bin', 'precert');

  // Helper function to reconstruct the precertificate data structure to verify the SCT against
  const precert = reconstructPrecert(leafCert, issuerCert);

  // A list of trusted logs
  const trustedLogs: Log[] = [
    {
      description: 'Fetched Google Test Log',
      key: getTrustedLogKey(),
      id: createHash('sha256')
        .update(getTrustedLogKey().export({ type: 'spki', format: 'der' }))
        .digest(),
      url: 'test.com',
      operated_by: 'Test',
      max_merge_delay: 0,
      status: 'usable',
    },
  ];

  const { log, sct } = verifySct(precertSct, precert, ENTRY_TYPE.PRECERT_ENTRY, Date.now(), trustedLogs);
  console.log(`Pre-cert SCT verification successful!`);
  console.log(`  Log ID: ${log.id.toString('hex')}`);
  console.log(`  Log: ${log.description}`);
  console.log(`  Timestamp: ${new Date(Number(sct.timestamp)).toISOString()}`);
} catch (error) {
  console.error('Error while verifying pre-certificate SCT:', error);
}

function getTrustedLogKey() {
  return createPublicKey({
    key: readTestData('log0-pubkey.bin', 'precert'),
    format: 'der',
    type: 'spki',
  });
}
