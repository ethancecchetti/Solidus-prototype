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

import com.google.common.collect.ImmutableList;
import org.bouncycastle.crypto.ec.ECPair;
import org.bouncycastle.math.ec.ECPoint;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import solidus.util.CryptoConstants;
import solidus.util.EncryptionParams;

import solidus.zkproofs.PlaintextEqDisKeyProof;

import test.util.TestUtils;

/**
 * Test suite for PlaintextDisKeyProver.
 *
 * @author fanz@cs.cornell.edu
 */

@RunWith(Parameterized.class)
public class PlaintextEqDisKeyProofTest {
    private static final EncryptionParams PARAMS = EncryptionParams.newTestParams(new Random(TestUtils.RANDOM_SEED),
            CryptoConstants.CURVE, CryptoConstants.DIGEST);

    @Parameterized.Parameters
    public static Collection<Object[]> data() {
        ECPoint publicKey1 = PARAMS.getGenerator()
                .multiply(new BigInteger("41c08663db2b002aa05665bdc147640d56aa519353f4c51bb06b8ae54b5a2edf", 16));
        ECPoint publicKey2 = PARAMS.getGenerator()
                .multiply(new BigInteger("58dbe2d54f045e910bf1f6896f3e55d18d278ae8d7176ada5c299305238cf30d", 16));

        BigInteger msg = new BigInteger("163d959a", 16);
        BigInteger msg2 = new BigInteger("a44fee07", 16);
        BigInteger rand1 = new BigInteger("44283477cf02e5d8dd9cf61eefd05e7575d08924b7a9ed20e1bc0f5b89d91032", 16);
        BigInteger rand2 = new BigInteger("4ed5d63df3ee80851a2a2a4be5c5b0fdc3e411a5247e840e1eb0fc5afa8186c2", 16);
        BigInteger rand3 = new BigInteger("589a225586a1f4f4e843f2adc1ec76e10ac49752546b83fe1025e3ab4d691eff", 16);
        BigInteger rand4 = new BigInteger("6cb4fa4e92c495232c4ec3fe8a798dbbc1a1fbe78ca20184d7c5b87d8c486d08", 16);

        ECPair cipher1 = new ECPair(PARAMS.getGenerator().multiply(msg).add(publicKey1.multiply(rand1)),
                PARAMS.getGenerator().multiply(rand1));
        ECPair cipher2 = new ECPair(PARAMS.getGenerator().multiply(msg).add(publicKey2.multiply(rand2)),
                PARAMS.getGenerator().multiply(rand2));

        return ImmutableList.copyOf(new Object[][] {
                { cipher1, cipher2, publicKey1, publicKey2, msg, rand1, rand2, cipher1, cipher2, publicKey1, publicKey2,
                        true },
                { cipher1, cipher2, publicKey1, publicKey2, msg2, rand1, rand2, cipher1, cipher2, publicKey1,
                        publicKey2, false },
                { cipher1, cipher2, publicKey1, publicKey2, msg, rand3, rand2, cipher1, cipher2, publicKey1, publicKey2,
                        false },
                { cipher1, cipher2, publicKey1, publicKey2, msg, rand1, rand4, cipher1, cipher2, publicKey1, publicKey2,
                        false }, });
    }

    private final ECPair m_buildCipher1, m_buildCipher2;
    private final ECPoint m_buildPKey1, m_buildPKey2;
    private final BigInteger m_msg;
    private final BigInteger m_rand1, m_rand2;

    private final ECPair m_verCipher1, m_verCipher2;
    private final ECPoint m_verPKey1, m_verPKey2;

    private final boolean m_shouldVerify;

    public PlaintextEqDisKeyProofTest(ECPair buildCipher1, ECPair buildCipher2, ECPoint buildPKey1, ECPoint buildPKey2,
            BigInteger msg, BigInteger rand1, BigInteger rand2, ECPair verCipher1, ECPair verCipher2, ECPoint verPKey1,
            ECPoint verPKey2, boolean shouldVerify) {
        m_buildCipher1 = buildCipher1;
        m_buildCipher2 = buildCipher2;
        m_buildPKey1 = buildPKey1;
        m_buildPKey2 = buildPKey2;
        m_msg = msg;
        m_rand1 = rand1;
        m_rand2 = rand2;

        m_verCipher1 = verCipher1;
        m_verCipher2 = verCipher2;
        m_verPKey1 = verPKey1;
        m_verPKey2 = verPKey2;

        m_shouldVerify = shouldVerify;
    }

    @Test
    public void testVerification() {
        PlaintextEqDisKeyProof proof = PlaintextEqDisKeyProof.buildProof(PARAMS, m_buildCipher1, m_buildCipher2,
                m_buildPKey1, m_buildPKey2, m_msg, m_rand1, m_rand2);

        Assert.assertEquals(m_shouldVerify, proof.verify(m_verCipher1, m_verCipher2, m_verPKey1, m_verPKey2));
        Assert.assertFalse(proof.verify(m_verCipher2, m_verCipher1, m_verPKey1, m_verPKey2));
        Assert.assertFalse(proof.verify(m_verCipher1, m_verCipher2, m_verPKey2, m_verPKey1));
        Assert.assertFalse(proof.verify(m_verCipher2, m_verCipher1, m_verPKey2, m_verPKey1));
    }

    /**
     * Tests to make sure all proofs serialize and deserialize properly,
     * regardless of the validity of the proof.
     */
    @Test
    public void testSerialization() {
        PlaintextEqDisKeyProof proof = PlaintextEqDisKeyProof.buildProof(PARAMS, m_buildCipher1, m_buildCipher2,
                m_buildPKey1, m_buildPKey2, m_msg, m_rand1, m_rand2);
        TestUtils.testSerialization(proof, PlaintextEqDisKeyProof::serialReadIn, PARAMS);
    }
}
