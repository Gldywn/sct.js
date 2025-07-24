import { execSync } from 'child_process';
import { writeFileSync, mkdirSync, existsSync } from 'fs';
import { join } from 'path';
import { createHash } from 'crypto';
import fetch from 'node-fetch';
import { BufferReader, decodePEM } from '../src/utils.js';
import { parseSct } from '../src/verify.js';
import { Certificate } from 'pkijs';
import { OctetString, fromBER } from 'asn1js';
import * as constants from '../src/constants.js';
import { getTestDataDir } from './utils.js';

const PRECERT_TESTDATA_DIR = getTestDataDir('precert');
const LOG_LIST_URL = 'https://www.gstatic.com/ct/log_list/v3/log_list.json';

async function main() {
  if (!existsSync(PRECERT_TESTDATA_DIR)) {
    console.log(`Creating output directory: ${PRECERT_TESTDATA_DIR}`);
    mkdirSync(PRECERT_TESTDATA_DIR, { recursive: true });
  }

  console.log('Fetching certificate chain from google.com...');
  const command = 'openssl s_client -connect google.com:443 -showcerts -servername google.com < /dev/null 2>/dev/null';
  const stdout = execSync(command, { encoding: 'utf-8' });

  const certs = stdout
    .split('-----END CERTIFICATE-----')
    .filter((pem) => pem.trim() !== '')
    .map((pem) => `${pem.trim()}\n-----END CERTIFICATE-----`);

  const leafCertPem = certs[0];
  const issuerCertPem = certs[1];

  const leafCertDer = Buffer.from(decodePEM(leafCertPem, 'CERTIFICATE')[0]);
  const issuerCertDer = Buffer.from(decodePEM(issuerCertPem, 'CERTIFICATE')[0]);

  writeFileSync(join(PRECERT_TESTDATA_DIR, 'leaf_google-cert.bin'), leafCertDer);
  writeFileSync(join(PRECERT_TESTDATA_DIR, 'issuer_google-cert.bin'), issuerCertDer);
  console.log('Saved leaf and issuer certificates.');

  // Manually find and parse the SCT extension
  const leafCert = Certificate.fromBER(leafCertDer);
  const sctListBuffer = ((): Buffer => {
    const sctExtension = leafCert.extensions?.find((ext) => ext.extnID === constants.SCT_EXTENSION_OID_V1);

    if (!sctExtension || !(sctExtension.extnValue instanceof OctetString)) {
      throw new Error('SCT extension is missing or invalid');
    }

    // Parse the content of the outer OCTET STRING
    const innerAsn1 = fromBER(sctExtension.extnValue.valueBlock.valueHexView);
    if (innerAsn1.offset === -1 || !(innerAsn1.result instanceof OctetString)) {
      throw new Error('Failed to parse inner SCT extension value');
    }

    // The value of the inner OCTET STRING is the raw SCT list.
    return Buffer.from(innerAsn1.result.valueBlock.valueHexView);
  })();

  // The SCT list is TLS-encoded. We'll parse it to grab the first two SCTs.
  const reader = new BufferReader(sctListBuffer);
  reader.readUInt16BE(); // Skip list length

  // Read and save the first SCT
  const sct0Length = reader.readUInt16BE();
  const sct0Buffer = reader.readBytes(sct0Length);
  writeFileSync(join(PRECERT_TESTDATA_DIR, 'google-sct0.bin'), sct0Buffer);
  console.log('Saved first SCT as google-sct0.bin.');

  // Read and save the second SCT
  const sct1Length = reader.readUInt16BE();
  const sct1Buffer = reader.readBytes(sct1Length);
  writeFileSync(join(PRECERT_TESTDATA_DIR, 'google-sct1.bin'), sct1Buffer);
  console.log('Saved second SCT as google-sct1.bin.');

  console.log('Fetching public log list...');
  const logListResponse = await fetch(LOG_LIST_URL);
  const logList = await logListResponse.json();
  const allLogs = logList.operators.flatMap((operator: any) => operator.logs);

  const scts = [sct0Buffer, sct1Buffer];
  for (let i = 0; i < scts.length; i++) {
    const sctBuffer = scts[i];
    const parsedSct = parseSct(sctBuffer);
    const sctLogId = parsedSct.logId.toString('hex');
    console.log(`Finding matching log for SCT ${i}...`);

    const foundLog = allLogs.find((log: any) => {
      const logKeyDer = Buffer.from(log.key, 'base64');
      const logId = createHash('sha256').update(logKeyDer).digest('hex');
      return logId === sctLogId;
    });

    if (foundLog) {
      const logKey = Buffer.from(foundLog.key, 'base64');
      console.log(`Found matching log for SCT ${i}: ${foundLog.description}`);
      writeFileSync(join(PRECERT_TESTDATA_DIR, `log${i}-pubkey.bin`), logKey);
      console.log(`Saved matching log key for SCT ${i}.`);
    } else {
      console.error(`ERROR: Could not find a matching log for SCT ${i}.`);
      process.exit(1);
    }
  }

  console.log('Precert test data fetching complete.');
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
