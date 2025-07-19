import { describe, it } from 'node:test';
import * as assert from 'node:assert';
import {
  verifySct,
  VerificationError,
  ENTRY_TYPE,
} from '../src/index.js';
import * as fixtures from './precert-google.fixtures.js';

describe('Pre-certificate SCT verification (Google)', () => {
    describe('SCT 0', () => {
        it('verifies a valid SCT', () => {
            assert.doesNotThrow(() => {
                verifySct(
                    fixtures.sct0,
                    fixtures.precert,
                    ENTRY_TYPE.PRECERT_ENTRY,
                    Date.now(),
                    [fixtures.log0]
                );
            });
        });

        it('fails to verify an SCT with a bad signature', () => {
            const badSctBuffer = Buffer.from(fixtures.sct0);
            badSctBuffer[badSctBuffer.length - 1] ^= 0xff;

            assert.throws(
                () =>
                    verifySct(
                        badSctBuffer,
                        fixtures.precert,
                        ENTRY_TYPE.PRECERT_ENTRY,
                        Date.now(),
                        [fixtures.log0]
                    ),
                { message: VerificationError.InvalidSignature },
                'Verification should fail with InvalidSignature'
            );
        });

        it('fails to verify against the wrong log', () => {
            assert.throws(
                () =>
                    verifySct(
                        fixtures.sct0,
                        fixtures.precert,
                        ENTRY_TYPE.PRECERT_ENTRY,
                        Date.now(),
                        [fixtures.log1]
                    ),
                { message: VerificationError.UnknownLog },
                'Verification should fail with UnknownLog'
            );
        });
    });

    describe('SCT 1', () => {
        it('verifies a valid SCT', () => {
            assert.doesNotThrow(() => {
                verifySct(
                    fixtures.sct1,
                    fixtures.precert,
                    ENTRY_TYPE.PRECERT_ENTRY,
                    Date.now(),
                    [fixtures.log1]
                );
            });
        });

        it('fails to verify an SCT with a bad signature', () => {
            const badSctBuffer = Buffer.from(fixtures.sct1);
            badSctBuffer[badSctBuffer.length - 1] ^= 0xff;

            assert.throws(
                () =>
                    verifySct(
                        badSctBuffer,
                        fixtures.precert,
                        ENTRY_TYPE.PRECERT_ENTRY,
                        Date.now(),
                        [fixtures.log1]
                    ),
                { message: VerificationError.InvalidSignature },
                'Verification should fail with InvalidSignature'
            );
        });

        it('fails to verify against the wrong log', () => {
            assert.throws(
                () =>
                    verifySct(
                        fixtures.sct1,
                        fixtures.precert,
                        ENTRY_TYPE.PRECERT_ENTRY,
                        Date.now(),
                        [fixtures.log0]
                    ),
                { message: VerificationError.UnknownLog },
                'Verification should fail with UnknownLog'
            );
        });
    });
}); 