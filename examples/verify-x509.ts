import { verifySct, ENTRY_TYPE, Log } from '../src/index.js';
import { jwkFromRawEcdsa, readTestData } from '../scripts/utils.js';

try {
  // The leaf certificate (end-entity), DER-encoded X.509
  const certificate = readTestData('google-cert.bin', 'x509');

  // The SCT, obtained either from the "signed_certificate_timestamp" TLS extension or OCSP response
  const sct = readTestData('google-sct0.bin', 'x509');

  // A list of trusted logs
  const trustedLogs: Log[] = [
    {
      description: "Google 'Pilot' log",
      key: jwkFromRawEcdsa(readTestData('google-pilot-pubkey.bin', 'x509')),
      id: Buffer.from('a4b90990b418581487bb13a2cc67700a3c359804f91bdfb8e377cd0ec80ddc10', 'hex'),
      url: 'ct.googleapis.com/pilot/',
      operated_by: 'Google',
      max_merge_delay: 86400,
      status: 'usable',
    },
  ];

  const { log, sct: parsedSct } = verifySct(sct, certificate, ENTRY_TYPE.X509_ENTRY, Date.now(), trustedLogs);
  console.log(`X.509 SCT verification successful!`);
  console.log(`  Log ID: ${log.id.toString('hex')}`);
  console.log(`  Log: ${log.description}`);
  console.log(`  Timestamp: ${new Date(Number(parsedSct.timestamp)).toISOString()}`);
} catch (error) {
  console.error('Error while verifying X.509 SCT:', error);
}
