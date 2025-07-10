import { Log } from '../src/types.js';
import { readTestData, jwkFromRawP256 } from './util.js';

export const GOOGLE_PILOT_LOG: Log = {
  description: "Google 'Pilot' log",
  url: 'ct.googleapis.com/pilot/',
  operated_by: 'Google',
  key: jwkFromRawP256(readTestData('google-pilot-pubkey.bin')),
  id: Buffer.from([
    164, 185, 9, 144, 180, 24, 88, 20, 135, 187, 19, 162, 204, 103, 112, 10, 60, 53, 152, 4, 249, 27, 223, 184, 227,
    119, 205, 14, 200, 13, 220, 16,
  ]),
  max_merge_delay: 86400,
};

export const SYMANTEC_LOG: Log = {
  description: 'Symantec log',
  url: 'ct.ws.symantec.com/',
  operated_by: 'Symantec',
  key: jwkFromRawP256(readTestData('symantec-log-pubkey.bin')),
  id: Buffer.from([
    221, 235, 29, 43, 122, 13, 79, 166, 32, 139, 129, 173, 129, 104, 112, 126, 46, 142, 157, 1, 213, 92, 136, 141, 61,
    17, 196, 205, 182, 236, 190, 204,
  ]),
  max_merge_delay: 86400,
};
