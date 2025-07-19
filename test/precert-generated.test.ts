import { describe, it } from 'node:test';
import * as assert from 'node:assert';
import { verifySct, VerificationError, ENTRY_TYPE } from '../src/index.js';
import * as fixtures from './precert-generated.fixtures.js';

for (const [alg, log] of Object.entries(fixtures.logs)) {
    describe(`Pre-certificate SCT verification for ${alg}`, () => {
        it('verifies a valid SCT', () => {
            assert.doesNotThrow(() => {
                verifySct(
                    fixtures.scts[alg].valid,
                    fixtures.precert,
                    ENTRY_TYPE.PRECERT_ENTRY,
                    Date.now(),
                    [log]
                );
            });
        });

        it('fails to verify an SCT with a future timestamp', () => {
            assert.throws(
                () =>
                    verifySct(
                        fixtures.scts[alg].future,
                        fixtures.precert,
                        ENTRY_TYPE.PRECERT_ENTRY,
                        Date.now(),
                        [log]
                    ),
                { message: VerificationError.TimestampInFuture },
                'Verification should fail with TimestampInFuture'
            );
        });

        it('fails to verify an SCT with a bad signature', () => {
            assert.throws(
                () =>
                    verifySct(
                        fixtures.scts[alg].badsig,
                        fixtures.precert,
                        ENTRY_TYPE.PRECERT_ENTRY,
                        Date.now(),
                        [log]
                    ),
                { message: VerificationError.InvalidSignature },
                'Verification should fail with InvalidSignature'
            );
        });

        it('fails to verify an SCT with the wrong log ID', () => {
            assert.throws(
                () =>
                    verifySct(
                        fixtures.scts[alg].wrongid,
                        fixtures.precert,
                        ENTRY_TYPE.PRECERT_ENTRY,
                        Date.now(),
                        [log]
                    ),
                { message: VerificationError.UnknownLog },
                'Verification should fail with LogNotFound'
            );
        });
    });
} 