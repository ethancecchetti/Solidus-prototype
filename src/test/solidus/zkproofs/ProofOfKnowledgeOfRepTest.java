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

import solidus.zkproofs.ProofOfKnowledgeOfRep;

import test.util.TestUtils;

@RunWith(Parameterized.class)
public class ProofOfKnowledgeOfRepTest {
    private static final EncryptionParams PARAMS = EncryptionParams.newTestParams(new Random(TestUtils.RANDOM_SEED),
            CryptoConstants.CURVE, CryptoConstants.DIGEST);

    @Parameters
    public static Collection<Object[]> data() {
        ECPoint publicKey = PARAMS.getGenerator()
                .multiply(new BigInteger("378f503ff3264aaca890e36b1228abc08ca673b72d920056642b804bec62a513", 16));

        BigInteger x = new BigInteger("5824dbd1f7985811bc7580bfca3134c5ada84e6326f572918eec90581103ca28", 16);
        BigInteger r = new BigInteger("5b3fcb395e245c02308cac730892dd74c2c75570616384d6482007c7eda54fa3", 16);
        ECPair cipher = new ECPair(PARAMS.getGenerator().multiply(x).add(publicKey.multiply(r)),
                PARAMS.getGenerator().multiply(r));

        ECPoint otherKey = PARAMS.getGenerator()
                .multiply(new BigInteger("7b04c5e76e81a155cec97707cd8961f972b917792134917605f74945486b9ff4", 16));
        BigInteger otherX = new BigInteger("71dbd2045c67a6a8c1223e0bd2271878ca8d9988cb4fb72fc1f0f3e1ea87c720", 16);
        BigInteger otherR = new BigInteger("6cf35ba7afaf7f67162a82cf44a14676ac3fed70a14e4685531459f679a15767", 16);

        byte[][] emptyMsg = new byte[0][];
        byte[][] msg = new byte[][] { { (byte) 0xa7, (byte) 0x2b, (byte) 0x67, (byte) 0xfd } };
        byte[][] msg2 = new byte[][] {
                { (byte) 0x07, (byte) 0xec, (byte) 0xc0, (byte) 0xbe, (byte) 0x6f, (byte) 0x6d, (byte) 0x91,
                        (byte) 0x4e },
                { (byte) 0xa7, (byte) 0x85, (byte) 0x42, (byte) 0x0a, (byte) 0x53, (byte) 0x15, (byte) 0xfb,
                        (byte) 0xd7 },
                { (byte) 0x53, (byte) 0x38, (byte) 0x7d, (byte) 0x6e, (byte) 0x62, (byte) 0xf6, (byte) 0xa2,
                        (byte) 0x34 },
                { (byte) 0xb2, (byte) 0x2f, (byte) 0xf5, (byte) 0x08, (byte) 0xd7, (byte) 0x2e, (byte) 0x54,
                        (byte) 0xc5 } };

        return ImmutableList.copyOf(new Object[][] { { cipher, publicKey, x, r, emptyMsg, publicKey, emptyMsg, true },
                { cipher, publicKey, x, r, msg, publicKey, msg, true },
                { cipher, publicKey, x, r, msg2, publicKey, msg2, true },
                { cipher, publicKey, x, r, emptyMsg, publicKey, msg, false },
                { cipher, publicKey, x, r, msg, publicKey, msg2, false },
                { cipher, publicKey, x, r, emptyMsg, otherKey, emptyMsg, false },
                { cipher, otherKey, x, r, emptyMsg, publicKey, emptyMsg, false },
                { cipher, publicKey, otherX, r, emptyMsg, publicKey, emptyMsg, false },
                { cipher, publicKey, x, otherR, emptyMsg, publicKey, emptyMsg, false },
                { cipher, otherKey, x, r, emptyMsg, otherKey, emptyMsg, false }, });
    }

    private final ECPair m_cipher;
    private final ECPoint m_buildKey;
    private final BigInteger m_x;
    private final BigInteger m_r;
    private final byte[][] m_buildMsg;

    private final ECPoint m_verKey;
    private final byte[][] m_verMsg;

    private final boolean m_shouldVerify;

    public ProofOfKnowledgeOfRepTest(ECPair cipher, ECPoint buildKey, BigInteger x, BigInteger r, byte[][] buildMsg,
            ECPoint verKey, byte[][] verMsg, boolean shouldVerify) {
        m_cipher = cipher;
        m_buildKey = buildKey;
        m_x = x;
        m_r = r;
        m_buildMsg = buildMsg;

        m_verKey = verKey;
        m_verMsg = verMsg;

        m_shouldVerify = shouldVerify;
    }

    @Test
    public void testVerification() {
        ProofOfKnowledgeOfRep proof = ProofOfKnowledgeOfRep.buildProof(PARAMS, m_cipher, m_buildKey, m_x, m_r,
                m_buildMsg);
        Assert.assertEquals(m_shouldVerify, proof.verify(m_verKey, m_verMsg));
    }

    @Test
    public void testSerialization() {
        ProofOfKnowledgeOfRep proof = ProofOfKnowledgeOfRep.buildProof(PARAMS, m_cipher, m_buildKey, m_x, m_r);
        TestUtils.testSerialization(proof, ProofOfKnowledgeOfRep::serialReadIn, PARAMS);
    }
}
