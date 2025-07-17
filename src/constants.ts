// Signature and hash algorithms
// From RFC 6962, section 7.4.1.4.1
export const SIGNATURE_ALGORITHMS = {
  // RSASSA-PKCS1-v1_5 with SHA-256
  RSA_PKCS1_SHA256: 0x0401,
  // RSASSA-PKCS1-v1_5 with SHA-384
  RSA_PKCS1_SHA384: 0x0501,
  // ECDSA with SHA-256
  ECDSA_SHA256: 0x0403,
  // ECDSA with SHA-384
  ECDSA_SHA384: 0x0503,
};

// SCT Version
export const SCT_V1 = 0;

// LogEntryType
export const LOG_ENTRY_TYPE = {
  X509_ENTRY: [0, 0],
  PRECERT_ENTRY: [0, 1],
};

// MerkleLeafType
export const MERKLE_LEAF_TYPE = {
  TIMESTAMPED_ENTRY: 0,
};

// OID for the SCT extension in X.509 certificates
// From RFC 6962, section 3.3
export const SCT_EXTENSION_OID_V1 = '1.3.6.1.4.1.11129.2.4.2';
