import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { VerificationError, shouldBeFatal } from '../src/types.js';

describe('Error handling policy', () => {
  test('unknown log should not be fatal', () => {
    assert.strictEqual(shouldBeFatal(VerificationError.UnknownLog), false);
  });

  test('unsupported sct version should not be fatal', () => {
    assert.strictEqual(shouldBeFatal(VerificationError.UnsupportedSctVersion), false);
  });

  test('other errors should be fatal', () => {
    assert.strictEqual(shouldBeFatal(VerificationError.MalformedSct), true);
    assert.strictEqual(shouldBeFatal(VerificationError.InvalidSignature), true);
    assert.strictEqual(shouldBeFatal(VerificationError.TimestampInFuture), true);
  });
});
