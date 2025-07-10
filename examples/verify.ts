import { verifySct } from '../dist/index.js';
import { jwkFromRawP256 } from '../test/util.ts';
import { readFileSync } from 'node:fs';

// In this example, we load the certificate from a local file for simplicity.
// In a real-world application, you would typically acquire this from a TLS
// connection.
const certificate = readFileSync('./test/testdata/google-cert.bin');

// Here, we load the SCT from a static file. In practice, SCTs are usually
// extracted from the certificate itself, a TLS extension, or an
// OCSP response.
const sct = readFileSync('./test/testdata/google-sct0.bin');

// Define the list of trusted Certificate Transparency logs. For production use,
// you should fetch and use a dynamic list of trusted logs from a reliable
// source such as the one maintained by Google.
// For more information, see: https://certificate.transparency.dev/google/
//
// This example manually constructs a list with a single log for demonstration,
// loading its public key from a local file.
const trustedLogs = [
  {
    description: "Google 'Pilot' log",
    key: jwkFromRawP256(readFileSync('./test/testdata/google-pilot-pubkey.bin')),
    id: Buffer.from('a4b90990b418581487bb13a2cc67700a3c359804f91bdfb8e377cd0ec80ddc10', 'hex'),
    url: 'ct.googleapis.com/pilot/',
    operated_by: 'Google',
    max_merge_delay: 86400,
  }
];

try {
  // Verify the SCT. A real implementation would use a recent timestamp to
  // ensure the SCT is currently valid. For this example, we use a fixed
  // timestamp from when the SCT was known to be valid to ensure the check
  // passes.
  const result = verifySct(certificate, sct, 1499619463644, trustedLogs);
  console.log(`SCT verification successful - Log: ${result.description}`);
} catch (error) {
  console.error(`SCT verification failed: ${error.message}`);
}