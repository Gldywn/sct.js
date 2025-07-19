import { createPublicKey, createHash } from 'crypto';
import { verifySct, reconstructPrecert, ENTRY_TYPE, Log } from '../src/index.js';
import { jwkFromRawP256, readTestData } from '../scripts/utils.js';

// =============================================================================
// Example 1: Verifying an SCT for an X.509 Certificate
// =============================================================================

try {
  // The final, DER-encoded X.509 certificate.
  const certificate = readTestData('google-cert.bin', 'x509');

  // The SCT, obtained either from the certificate or a TLS extension.
  const sct = readTestData('google-sct0.bin', 'x509');

  // A list of trusted logs. In a real application, this should be a dynamic,
  // up-to-date list from a trusted source.
  const x509TrustedLogs: Log[] = [
    {
      description: "Google 'Pilot' log",
      key: jwkFromRawP256(readTestData('google-pilot-pubkey.bin', 'x509')),
      id: Buffer.from('a4b90990b418581487bb13a2cc67700a3c359804f91bdfb8e377cd0ec80ddc10', 'hex'),
      url: 'ct.googleapis.com/pilot/',
      operated_by: 'Google',
      max_merge_delay: 86400,
    },
  ];

  const x509Result = verifySct(sct, certificate, ENTRY_TYPE.X509_ENTRY, Date.now(), x509TrustedLogs);
  console.log(`X.509 SCT verification successful - Log: ${x509Result.description}`);
} catch (error) {
  console.error(`SCT verification failed: ${error.message}`);
}

// =============================================================================
// Example 2: Verifying an SCT for a Pre-certificate
// =============================================================================

try {
  // The leaf certificate and the issuer's certificate are required.
  const leafCert = readTestData('leaf_google-cert.bin', 'precert');
  const issuerCert = readTestData('issuer_google-cert.bin', 'precert');

  // The SCT for the pre-certificate.
  const precertSct = readTestData('google-sct0.bin', 'precert');

  // The public key for the log that issued the SCT.
  const logKey = createPublicKey({
    key: readTestData('log0-pubkey.bin', 'precert'),
    format: 'der',
    type: 'spki',
  });

  // A list of trusted logs.
  const precertTrustedLogs: Log[] = [
    {
      description: 'Fetched Google Test Log',
      key: logKey,
      id: createHash('sha256')
        .update(logKey.export({ type: 'spki', format: 'der' }))
        .digest(),
      url: 'test.com',
      operated_by: 'Test',
      max_merge_delay: 0,
    },
  ];

  // 1. Reconstruct the precertificate data structure
  const precert = reconstructPrecert(leafCert, issuerCert);

  // 2. Verify the SCT against the reconstructed precert
  const precertResult = verifySct(precertSct, precert, ENTRY_TYPE.PRECERT_ENTRY, Date.now(), precertTrustedLogs);
  console.log(`Pre-cert SCT verification successful - Log: ${precertResult.description}`);
} catch (error) {
  console.error(`Pre-cert SCT verification failed: ${error.message}`);
}
