import { describe, it } from 'node:test';
import * as assert from 'node:assert';
import { verifySct, VerificationError, ENTRY_TYPE, Log } from '../src/index.js';
import * as fixtures from './precert-generated.fixtures.js';

describe('Verifying SCTs from retired logs', () => {
  // Use a single, representative log for these tests
  const log = fixtures.logs['ecdsa-p256'];
  const sct = fixtures.scts['ecdsa-p256'].valid;
  const precert = fixtures.precert;

  it('verifies a valid SCT from a retired log', () => {
    const { sct: parsedSct } = verifySct(sct, precert, ENTRY_TYPE.PRECERT_ENTRY, Date.now(), [log]);

    // Create a retired log with a retirement date AFTER the SCT's timestamp
    const retiredLog: Log = {
      ...log,
      status: 'retired',
      retirement_date: Number(parsedSct.timestamp) + 1,
    };

    assert.doesNotThrow(() => {
      verifySct(sct, precert, ENTRY_TYPE.PRECERT_ENTRY, Date.now(), [retiredLog]);
    }, 'Verification should succeed for a retired log with a timely SCT');
  });

  it('fails to verify an SCT from a retired log issued after its retirement date', () => {
    const { sct: parsedSct } = verifySct(sct, precert, ENTRY_TYPE.PRECERT_ENTRY, Date.now(), [log]);

    // Create a retired log with a retirement date BEFORE the SCT's timestamp
    const retiredLog: Log = {
      ...log,
      status: 'retired',
      retirement_date: Number(parsedSct.timestamp) - 1,
    };

    assert.throws(
      () => verifySct(sct, precert, ENTRY_TYPE.PRECERT_ENTRY, Date.now(), [retiredLog]),
      { code: VerificationError.SctFromRetiredLog },
      'Verification should fail for a retired log with an untimely SCT',
    );
  });
});
