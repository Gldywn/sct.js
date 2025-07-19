# SCT.js

SCT.js is a Certificate Transparency SCT verifier in TypeScript for Node.js.
It uses the built-in `node:crypto` module for all cryptographic operations.

[![Build Status](https://github.com/Gldywn/sct.js/actions/workflows/build.yml/badge.svg)](https://github.com/Gldywn/sct.js/actions/workflows/build.yml)
[![Coverage Status (codecov.io)](https://codecov.io/gh/Gldywn/sct.js/branch/main/graph/badge.svg)](https://codecov.io/gh/Gldywn/sct.js)
[![npm](https://img.shields.io/npm/v/@gldywn/sct.js.svg)](https://www.npmjs.com/package/@gldywn/sct.js)

## Status

- The library is stable and ready for production use.
- Supports both **X.509** and **Pre-certificate** SCT entries.
- The test suite for X.509 entries is ported from the original Rust library. It has been augmented with a comprehensive, generated test suite for Pre-certificate entries, covering all success and error cases for multiple signature algorithms (ECDSA P-256/P-384, RSA 2048/3072/4096).

## How SCTs are Acquired

Signed Certificate Timestamps (SCTs) are the core of Certificate Transparency, but they can be delivered to a client in several ways. This library is responsible for the *verification* of an SCT, regardless of how it was acquired. It is the responsibility of the client application to obtain the certificate and its associated SCTs.

There are three primary methods for delivering SCTs:

1.  **Embedded in the Certificate:** The SCT is included directly in the final X.509 certificate as an extension (`1.3.6.1.4.1.11129.2.4.2`). This is the most common method.
2.  **Via a TLS Extension:** The SCT is delivered during the TLS handshake via the `signed_certificate_timestamp` extension. This is useful for certificates issued before the log was trusted, or when the CA is not participating in CT.
3.  **Via OCSP Stapling:** The SCT is included in a stapled OCSP response, which is sent by the server during the TLS handshake.

This library can verify SCTs from any of these sources, provided you can supply the SCT data and the certificate or pre-certificate data it corresponds to.

## Installation

```sh
npm install @gldywn/sct.js
```

## Usage

The following example demonstrates how to verify Signed Certificate Timestamps (SCTs) for both standard X.509 certificates and for pre-certificates:

```typescript
import { createPublicKey, createHash } from 'crypto';
import { verifySct, reconstructPrecert, ENTRY_TYPE, Log } from '@gldywn/sct.js';
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
```

## Test

This project includes a comprehensive test suite to ensure correctness and stability.

### Updating Test Data

The repository includes pre-generated test data. To update the fixtures for pre-certificate tests, run:

```sh
npm run test:setup
```

This command performs the following steps:
1.  **Generates test keys:** Creates new key pairs for all supported algorithms.
2.  **Generates pre-cert data:** Builds a fresh suite of mock SCTs and test cases.
3.  **Fetches real-world data:** Downloads the latest test certificates from Google.

### Running Tests

To run the complete test suite:
```sh
npm test
```

## License

SCT.js is distributed under the MIT license.

## Browser Compatibility

This library is currently intended for **Node.js environments only**.

It relies on Node.js built-in modules like `crypto` and `Buffer` that are not available in web browsers. While it is theoretically possible to use this library in a browser by using polyfills (such as `crypto-browserify` and `buffer`), this is not officially supported or tested at this time. Future versions may include a browser-compatible bundle.

## Acknowledgements

This library is a full-featured TypeScript port of the excellent [rustls/sct.rs](https://github.com/rustls/sct.rs) library. It is designed to be a 1:1 functional equivalent and includes a faithful port of the original's comprehensive test suite to ensure correctness.
