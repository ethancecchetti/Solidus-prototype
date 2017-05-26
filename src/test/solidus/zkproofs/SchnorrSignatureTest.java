/*
 * Solidus - Confidential Distributed Ledger Transactions via PVORM
 *
 * Copyright 2016-2017 Ethan Cecchetti, Fan Zhang and Yan Ji
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package test.solidus.zkproofs;

import com.google.common.collect.ImmutableList;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import solidus.util.CryptoConstants;
import solidus.util.EncryptionParams;
import solidus.zkproofs.SchnorrSignature;
import test.util.TestUtils;

import java.math.BigInteger;
import java.util.Collection;
import java.util.Random;

/**
 * Test suite for SchnorrSignature.
 *
 * @author fanz@cs.cornell.edu
 */

@RunWith(Parameterized.class)
public class SchnorrSignatureTest {
    private static final int MESSAGE_LENGTH = 1000;
    private static final EncryptionParams PARAMS = EncryptionParams.newTestParams(new Random(TestUtils.RANDOM_SEED),
            CryptoConstants.CURVE, CryptoConstants.DIGEST);

    @Parameters
    public static Collection<Object[]> data() {
        BigInteger signKey = PARAMS.getRandomIndex();
        ECPoint verKey = PARAMS.getGenerator().multiply(signKey);

        BigInteger otherSignKey = PARAMS.getRandomIndex();
        ECPoint otherVerKey = PARAMS.getGenerator().multiply(otherSignKey);

        byte[] message = new byte[MESSAGE_LENGTH];
        PARAMS.getRandomSource().nextBytes(message);
        byte[] otherMessage = new byte[MESSAGE_LENGTH];
        PARAMS.getRandomSource().nextBytes(otherMessage);

        SchnorrSignature sig = SchnorrSignature.sign(PARAMS, signKey, message);

        return ImmutableList
                .copyOf(new Object[][] { { message, sig, verKey, true }, { message, sig, otherVerKey, false },
                        { otherMessage, sig, verKey, false }, { otherMessage, sig, otherVerKey, false }, });
    }

    private final byte[] m_message;
    private final SchnorrSignature m_signature;
    private final ECPoint m_publicKey;
    private final boolean m_shouldVerify;

    public SchnorrSignatureTest(byte[] message, SchnorrSignature signature, ECPoint publicKey, boolean shouldVerify) {
        m_message = message;
        m_signature = signature;
        m_publicKey = publicKey;
        m_shouldVerify = shouldVerify;
    }

    @Test
    public void testVerification() {
        Assert.assertEquals(m_shouldVerify, m_signature.verify(m_publicKey, m_message));
    }

    @Test
    public void testSerialization() {
        TestUtils.testSerialization(m_signature, SchnorrSignature::serialReadIn, PARAMS);
    }
}
