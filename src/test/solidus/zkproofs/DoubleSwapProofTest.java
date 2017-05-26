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

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.Collection;
import java.util.Random;

import org.bouncycastle.crypto.ec.ECPair;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import com.google.common.collect.ImmutableList;

import solidus.util.CryptoConstants;
import solidus.util.EncryptionParams;
import solidus.util.Encryptor;

import solidus.zkproofs.DoubleSwapProof;

import test.util.TestUtils;

/**
 * Unit tests for DoubleSwapProof.
 *
 * @see solidus.zkproofs.DoubleSwapProof
 *
 * @author ethan@cs.cornell.edu
 */
@RunWith(Parameterized.class)
public class DoubleSwapProofTest {
    private static final EncryptionParams PARAMS = EncryptionParams.newTestParams(new Random(TestUtils.RANDOM_SEED),
            CryptoConstants.CURVE, CryptoConstants.DIGEST);

    @Parameters
    public static Collection<Object[]> data() {
        BigInteger secretKey = new BigInteger("23544bda2d7022e6bd82dd979541a4c29fb1785b40924ba728eda77c96068907", 16);
        ECPoint publicKey = PARAMS.getGenerator().multiply(secretKey);
        Encryptor encryptor = PARAMS.getEncryptor(publicKey);

        ECPair initCipher1 = encryptor
                .encryptValue(new BigInteger("3667c3f7adcd84fe4bc4cb1632a9ad4aa80bb453d92191d491c5c90f4874938e", 16));
        ECPair initCipher2 = encryptor
                .encryptValue(new BigInteger("6e4e1a3b16ecb69a35eb902bf58b2ed6072ee424777a14e74de8091e7d5a339d", 16));
        ECPair initCipher3 = encryptor
                .encryptValue(new BigInteger("580b7dbd732b8d6f4e158744162b7fb198f1f6680befcbd2b773c0d55f69d010", 16));
        ECPair initCipher4 = encryptor
                .encryptValue(new BigInteger("10955708b640e5a434b6cc8e4ffaad25c0bf338c2ded2a064fa5b892e0bdf151", 16));

        ECPair reCipher1 = encryptor.reencrypt(initCipher1);
        ECPair reCipher2 = encryptor.reencrypt(initCipher2);
        ECPair reCipher3 = encryptor.reencrypt(initCipher3);
        ECPair reCipher4 = encryptor.reencrypt(initCipher4);

        BigInteger otherSecretKey = secretKey.add(BigInteger.ONE);
        ECPoint otherPublicKey = publicKey.add(PARAMS.getGenerator());

        return ImmutableList.copyOf(new Object[][] {
                { new Pair(initCipher1, initCipher2), new Pair(initCipher3, initCipher4),
                        new Pair(reCipher1, reCipher2), new Pair(reCipher3, reCipher4), publicKey, secretKey, true,
                        true },
                { new Pair(initCipher1, initCipher2), new Pair(initCipher3, initCipher4),
                        new Pair(reCipher3, reCipher4), new Pair(reCipher1, reCipher2), publicKey, secretKey, false,
                        true },
                { new Pair(initCipher1, initCipher2), new Pair(initCipher3, initCipher4),
                        new Pair(reCipher2, reCipher1), new Pair(reCipher4, reCipher3), publicKey, secretKey, true,
                        false },
                { new Pair(initCipher1, initCipher2), new Pair(initCipher3, initCipher4),
                        new Pair(reCipher4, reCipher3), new Pair(reCipher2, reCipher1), publicKey, secretKey, false,
                        false },
                { new Pair(initCipher1, initCipher2), new Pair(initCipher3, initCipher4),
                        new Pair(reCipher3, reCipher4), new Pair(reCipher1, reCipher2), publicKey, secretKey, true,
                        false },
                { new Pair(initCipher1, initCipher2), new Pair(initCipher3, initCipher4),
                        new Pair(reCipher1, reCipher2), new Pair(reCipher3, reCipher4), publicKey, secretKey, false,
                        false },
                { new Pair(initCipher1, initCipher2), new Pair(initCipher3, initCipher4),
                        new Pair(reCipher3, reCipher2), new Pair(reCipher1, reCipher4), publicKey, secretKey, false,
                        false },
                { new Pair(initCipher1, initCipher2), new Pair(initCipher3, initCipher4),
                        new Pair(reCipher3, reCipher2), new Pair(reCipher1, reCipher4), publicKey, secretKey, true,
                        false },
                { new Pair(initCipher1, initCipher2), new Pair(initCipher3, initCipher4),
                        new Pair(reCipher1, reCipher2), new Pair(reCipher1, reCipher2), publicKey, secretKey, true,
                        false },
                { new Pair(initCipher1, initCipher2), new Pair(initCipher3, initCipher4),
                        new Pair(reCipher1, reCipher2), new Pair(reCipher3, reCipher4), publicKey, otherSecretKey, true,
                        false },
                { new Pair(initCipher1, initCipher2), new Pair(initCipher3, initCipher4),
                        new Pair(reCipher1, reCipher2), new Pair(reCipher3, reCipher4), otherPublicKey, secretKey, true,
                        false },
                { new Pair(initCipher1, initCipher2), new Pair(initCipher3, initCipher4),
                        new Pair(reCipher1, reCipher2), new Pair(reCipher3, reCipher4), otherPublicKey, otherSecretKey,
                        true, false }, });
    }

    public static class Pair implements DoubleSwapProof.CipherPair {
        private final ECPair m_cipher1;
        private final ECPair m_cipher2;

        public Pair(ECPair cipher1, ECPair cipher2) {
            m_cipher1 = cipher1;
            m_cipher2 = cipher2;
        }

        @Override
        public ECPair getCipher1() {
            return m_cipher1;
        }

        @Override
        public ECPair getCipher2() {
            return m_cipher2;
        }

        @Override
        public void serialWriteOut(OutputStream outStream, boolean compressPoints) throws IOException {
            throw new UnsupportedOperationException();
        }
    }

    private final Pair m_preSwap1;
    private final Pair m_preSwap2;
    private final Pair m_postSwap1;
    private final Pair m_postSwap2;
    private final ECPoint m_publicKey;
    private final BigInteger m_secretKey;
    private final boolean m_isFake;
    private final boolean m_shouldVerify;

    public DoubleSwapProofTest(Pair preSwap1, Pair preSwap2, Pair postSwap1, Pair postSwap2, ECPoint publicKey,
            BigInteger secretKey, boolean isFake, boolean shouldVerify) {
        m_preSwap1 = preSwap1;
        m_preSwap2 = preSwap2;
        m_postSwap1 = postSwap1;
        m_postSwap2 = postSwap2;
        m_publicKey = publicKey;
        m_secretKey = secretKey;
        m_isFake = isFake;
        m_shouldVerify = shouldVerify;
    }

    @Test
    public void testVerification() {
        DoubleSwapProof proof = DoubleSwapProof.buildProof(PARAMS, m_preSwap1, m_preSwap2, m_postSwap1, m_postSwap2,
                m_publicKey, m_secretKey, m_isFake);
        Assert.assertEquals(m_shouldVerify,
                proof.verify(m_preSwap1, m_preSwap2, m_postSwap1, m_postSwap2, m_publicKey));
    }

    @Test
    public void testSerialization() {
        DoubleSwapProof proof = DoubleSwapProof.buildProof(PARAMS, m_preSwap1, m_preSwap2, m_postSwap1, m_postSwap2,
                m_publicKey, m_secretKey, m_isFake);
        TestUtils.testSerialization(proof, DoubleSwapProof::serialReadIn, PARAMS);
    }
}
