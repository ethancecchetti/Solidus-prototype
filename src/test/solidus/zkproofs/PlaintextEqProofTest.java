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
import solidus.zkproofs.PlaintextEqProof;

import test.util.TestUtils;

/**
 * Test suite for PlaintextEqProof that tests correctness of all important
 * operations.
 *
 * @see solidus.zkproofs.PlaintextEqProof
 *
 * @author ethan@cs.cornell.edu
 */
@RunWith(Parameterized.class)
public class PlaintextEqProofTest {
    private static final EncryptionParams PARAMS = EncryptionParams.newTestParams(new Random(TestUtils.RANDOM_SEED),
            CryptoConstants.CURVE, CryptoConstants.DIGEST);

    @Parameters
    public static Collection<Object[]> data() {
        BigInteger secretKey = new BigInteger("46e5753435a873ca8589c9fe87627110140b45af36d305715ea88c966c0857d8", 16);

        ECPoint publicKey = PARAMS.getGenerator().multiply(secretKey).normalize();
        Encryptor encryptor = PARAMS.getEncryptor(publicKey);

        ECPair initCipher = encryptor
                .encryptValue(new BigInteger("296b6707ad3ea5fd6203767c3b997a5428b42b4ed6365c7d536b5eede11a6c63", 16));
        ECPair reCipher = encryptor.reencrypt(initCipher);

        BigInteger otherSecretKey = new BigInteger("996e6ce302a6750ec95402d7e96fa7e283927535787643098acc7e0f1338a5c9",
                16);
        ECPoint otherPublicKey = PARAMS.getGenerator().multiply(otherSecretKey);
        ECPair otherCipher = new ECPair(initCipher.getX().add(PARAMS.getGenerator()), initCipher.getY());

        return ImmutableList
                .copyOf(new Object[][] { { initCipher, reCipher, publicKey, secretKey, reCipher, publicKey, true },
                        { initCipher, reCipher, publicKey, secretKey, otherCipher, publicKey, false },
                        { initCipher, reCipher, publicKey, secretKey, reCipher, otherPublicKey, false },
                        { initCipher, otherCipher, publicKey, secretKey, otherCipher, publicKey, false },
                        { initCipher, reCipher, publicKey, otherSecretKey, reCipher, publicKey, false },
                        { initCipher, reCipher, otherPublicKey, secretKey, reCipher, publicKey, false },
                        { initCipher, reCipher, otherPublicKey, secretKey, reCipher, otherPublicKey, false },
                        { initCipher, reCipher, otherPublicKey, otherSecretKey, reCipher, otherPublicKey, false } });
    }

    private final ECPair m_initCipher;
    private final ECPair m_newCipher;
    private final ECPoint m_publicKey;
    private final BigInteger m_secretKey;

    private final ECPair m_verNewCipher;
    private final ECPoint m_verPublicKey;

    private final boolean m_shouldVerify;

    public PlaintextEqProofTest(ECPair initCipher, ECPair newCipher, ECPoint publicKey, BigInteger secretKey,
            ECPair verNewCipher, ECPoint verPublicKey, boolean shouldVerify) {
        m_initCipher = initCipher;
        m_newCipher = newCipher;
        m_publicKey = publicKey;
        m_secretKey = secretKey;
        m_verNewCipher = verNewCipher;
        m_verPublicKey = verPublicKey;
        m_shouldVerify = shouldVerify;
    }

    /**
     * Tests to make sure valid proofs verify and invalid ones do not.
     */
    @Test
    public void testVerification() {
        PlaintextEqProof proof = PlaintextEqProof.buildProof(PARAMS, m_initCipher, m_newCipher, m_publicKey,
                m_secretKey);

        Assert.assertEquals(m_shouldVerify, proof.verify(m_initCipher, m_verNewCipher, m_verPublicKey));
    }

    /**
     * Tests to make sure all proofs serialize and deserialize properly,
     * regardless of the validity of the proof.
     */
    @Test
    public void testSerialization() {
        PlaintextEqProof proof = PlaintextEqProof.buildProof(PARAMS, m_initCipher, m_newCipher, m_publicKey,
                m_secretKey);
        TestUtils.testSerialization(proof, PlaintextEqProof::serialReadIn, PARAMS);
    }
}
