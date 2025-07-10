# SCT.js

> This is a full-featured TypeScript port of the excellent [rustls/sct.rs](https://github.com/rustls/sct.rs) library. It is designed to be a 1:1 functional equivalent and includes a faithful port of the original's comprehensive test suite to ensure correctness.

SCT.js is a Certificate Transparency SCT verifier in TypeScript for Node.js.
It uses the built-in `node:crypto` module for all cryptographic operations.

[![Build Status](https://github.com/Gldywn/sct.js/actions/workflows/build.yml/badge.svg)](https://github.com/Gldywn/sct.js/actions/workflows/build.yml)
[![Coverage Status (codecov.io)](https://codecov.io/gh/Gldywn/sct.js/branch/main/graph/badge.svg)](https://codecov.io/gh/Gldywn/sct.js)
[![npm](https://img.shields.io/npm/v/@gldywn/sct.js.svg)](https://www.npmjs.com/package/@gldywn/sct.js)

# Status
Ready for use:

- All intended features are implemented.
- The test suite is ported from the original library, covering all success and error cases.

# License
SCT.js is distributed under the MIT license.

# Browser Compatibility
This library is currently intended for **Node.js environments only**.

It relies on Node.js built-in modules like `crypto` and `Buffer` that are not available in web browsers. While it is theoretically possible to use this library in a browser by using polyfills (such as `crypto-browserify` and `buffer`), this is not officially supported or tested at this time. Future versions may include a browser-compatible bundle.
