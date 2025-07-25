import { createPublicKey, KeyObject } from 'crypto';
import { Log } from '../src/types.js';
import { readTestData, jwkFromRawEcdsa } from '../scripts/utils.js';

function pkcs1FromRawRsa(rawPublicKey: Buffer): KeyObject {
  return createPublicKey({
    key: rawPublicKey,
    format: 'der',
    type: 'pkcs1',
  });
}

export const TEST_LOG_ECDSA_P256: Log = {
  description: 'fake test ecdsa_p256 log',
  url: '',
  operated_by: 'random python script',
  max_merge_delay: 0,
  key: jwkFromRawEcdsa(readTestData('ecdsa-prime256v1-pub.raw', 'x509')),
  id: Buffer.from([
    0x71, 0xdc, 0x5e, 0xdb, 0xf0, 0x13, 0xd3, 0x88, 0x8a, 0x14, 0x6f, 0x49, 0x3d, 0xbe, 0x33, 0x94, 0xbb, 0x5a, 0xdb,
    0x65, 0xb2, 0x6a, 0x96, 0xe2, 0x38, 0x35, 0x4e, 0xd4, 0x8f, 0xeb, 0xb2, 0x4f,
  ]),
  status: 'usable',
};

export const TEST_LOG_ECDSA_P384: Log = {
  description: 'fake test ecdsa_p384 log',
  url: '',
  operated_by: 'random python script',
  max_merge_delay: 0,
  key: jwkFromRawEcdsa(readTestData('ecdsa-secp384r1-pub.raw', 'x509')),
  id: Buffer.from([
    0x29, 0xbb, 0xef, 0x00, 0xba, 0xd9, 0x3d, 0x5d, 0x4c, 0x03, 0xc7, 0x29, 0xe9, 0x4d, 0xb6, 0xac, 0x00, 0xe0, 0xfd,
    0x28, 0xf6, 0x46, 0x56, 0x37, 0x24, 0xac, 0x58, 0xdc, 0x66, 0xb1, 0x99, 0xe9,
  ]),
  status: 'usable',
};

export const TEST_LOG_RSA2048: Log = {
  description: 'fake test rsa2048 log',
  url: '',
  operated_by: 'random python script',
  max_merge_delay: 0,
  key: pkcs1FromRawRsa(readTestData('rsa-2048-pub.raw', 'x509')),
  id: Buffer.from([
    0x6e, 0x56, 0xa6, 0x5e, 0x21, 0x40, 0x97, 0x71, 0xeb, 0xbd, 0x16, 0x67, 0xc3, 0x37, 0x39, 0xb3, 0x35, 0x0e, 0xb2,
    0xee, 0x9f, 0x3a, 0x55, 0x4c, 0xf3, 0x37, 0x12, 0xc0, 0x6a, 0x1a, 0x72, 0x0a,
  ]),
  status: 'usable',
};

export const TEST_LOG_RSA3072: Log = {
  description: 'fake test rsa3072 log',
  url: '',
  operated_by: 'random python script',
  max_merge_delay: 0,
  key: pkcs1FromRawRsa(readTestData('rsa-3072-pub.raw', 'x509')),
  id: Buffer.from([
    0xb4, 0xcd, 0x74, 0xe7, 0x69, 0x59, 0xb3, 0x4e, 0xbb, 0x90, 0x80, 0xba, 0x9e, 0xaa, 0x08, 0xaf, 0x75, 0x8b, 0x52,
    0x7b, 0xbb, 0x5f, 0xf7, 0x24, 0x59, 0x8f, 0xfa, 0xc7, 0x37, 0x65, 0x49, 0xb0,
  ]),
  status: 'usable',
};

export const TEST_LOG_RSA4096: Log = {
  description: 'fake test rsa4096 log',
  url: '',
  operated_by: 'random python script',
  max_merge_delay: 0,
  key: pkcs1FromRawRsa(readTestData('rsa-4096-pub.raw', 'x509')),
  id: Buffer.from([
    0xfb, 0x56, 0x27, 0x12, 0xec, 0xa0, 0xf0, 0xdc, 0x7f, 0x06, 0xda, 0x76, 0xab, 0xba, 0x5d, 0x88, 0x28, 0x2b, 0x62,
    0xc5, 0x71, 0xf6, 0x0d, 0x69, 0x41, 0x94, 0x85, 0x16, 0xc8, 0x22, 0xf3, 0x29,
  ]),
  status: 'usable',
};
