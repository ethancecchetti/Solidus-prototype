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

import org.bouncycastle.math.ec.ECPoint;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import com.google.common.collect.ImmutableList;

import solidus.util.CryptoConstants;
import solidus.util.EncryptionParams;
import solidus.zkproofs.OneOfTwoDlogProof;

import test.util.TestUtils;

@RunWith(Parameterized.class)
public class OneOfTwoDlogProofTest {
    private static final EncryptionParams PARAMS = EncryptionParams.newTestParams(new Random(TestUtils.RANDOM_SEED),
            CryptoConstants.CURVE, CryptoConstants.DIGEST);

    private static final ECPoint GEN = PARAMS.getGenerator();

    private static final BigInteger SECRET_KEY = new BigInteger(
            "1137f51aa5d467475533a0a7fc96164608aa09cd25e476bee9fb284ad7e7cfb4", 16);
    private static final ECPoint PUBLIC_KEY = PARAMS.getGenerator().multiply(SECRET_KEY);

    private static final ECPoint OTHER_PUBLIC_KEY = PARAMS.getGenerator()
            .multiply(new BigInteger("52f386908ddd1e4e3809ae6629ce3b2fea525db9fbb416d38acbea18c7054405", 16));

    private static final ECPoint RAND_BASE = PARAMS.getGenerator()
            .multiply(new BigInteger("65885b7003f39c0e73f02b6fabb3404c01d6ee2ed1e012a0a4a4871d70414692", 16));
    private static final ECPoint RAND_POINT = PARAMS.getGenerator()
            .multiply(new BigInteger("603c6d7243a3a4408cbaffa90a11daeef6e3cd37fc505ac2ed87d00d956a194d", 16));

    @Parameters
    public static Collection<Object[]> data() {
        return ImmutableList.copyOf(new Object[][] {
                { GEN, GEN, PARAMS.getInfinity(), GEN, BigInteger.ONE, true, true },
                { GEN, GEN, PARAMS.getInfinity(), GEN, BigInteger.ONE, false, false },
                { GEN, PARAMS.getInfinity(), GEN, GEN, BigInteger.ONE, false, true },
                { GEN, PARAMS.getInfinity(), GEN, GEN, BigInteger.ONE, true, false },
                { GEN, GEN, GEN, GEN, BigInteger.ONE, true, true }, { GEN, GEN, GEN, GEN, BigInteger.ONE, false, true },
                { GEN, PUBLIC_KEY, GEN, PUBLIC_KEY, SECRET_KEY, true, true },
                { GEN, PUBLIC_KEY, GEN, PUBLIC_KEY, SECRET_KEY, false, false },
                { GEN, GEN, PUBLIC_KEY, PUBLIC_KEY, SECRET_KEY, false, true },
                { GEN, GEN, PUBLIC_KEY, PUBLIC_KEY, SECRET_KEY, true, false },
                { RAND_BASE, RAND_BASE.multiply(SECRET_KEY), GEN, PUBLIC_KEY, SECRET_KEY, true, true },
                { RAND_BASE, RAND_BASE.multiply(SECRET_KEY), GEN, PUBLIC_KEY, SECRET_KEY, false, false },
                { RAND_BASE, GEN, RAND_BASE.multiply(SECRET_KEY), PUBLIC_KEY, SECRET_KEY, false, true },
                { RAND_BASE, GEN, RAND_BASE.multiply(SECRET_KEY), PUBLIC_KEY, SECRET_KEY, true, false },
                { RAND_BASE, GEN, RAND_POINT, PUBLIC_KEY, SECRET_KEY, true, false },
                { RAND_BASE, GEN, RAND_POINT, PUBLIC_KEY, SECRET_KEY, false, false }, });
    }

    private final ECPoint m_base;
    private final ECPoint m_point1;
    private final ECPoint m_point2;

    private final ECPoint m_publicKey;
    private final BigInteger m_secretKey;

    private final boolean m_useFirst;
    private final boolean m_shouldVerify;

    public OneOfTwoDlogProofTest(ECPoint base, ECPoint point1, ECPoint point2, ECPoint publicKey, BigInteger secretKey,
            boolean useFirst, boolean shouldVerify) {
        m_base = base;
        m_point1 = point1;
        m_point2 = point2;

        m_publicKey = publicKey;
        m_secretKey = secretKey;

        m_useFirst = useFirst;
        m_shouldVerify = shouldVerify;
    }

    @Test
    public void testVerification() {
        OneOfTwoDlogProof proof = OneOfTwoDlogProof.buildProof(PARAMS, m_base, m_point1, m_point2, m_publicKey,
                m_secretKey, m_useFirst);
        Assert.assertEquals(m_shouldVerify, proof.verify(m_base, m_point1, m_point2, m_publicKey));
        Assert.assertEquals(m_shouldVerify && m_point1.equals(m_point2),
                proof.verify(m_base, m_point2, m_point1, m_publicKey));
        Assert.assertFalse(proof.verify(m_base, m_point1, m_point2, OTHER_PUBLIC_KEY));
    }

    @Test
    public void testSerialization() {
        OneOfTwoDlogProof proof = OneOfTwoDlogProof.buildProof(PARAMS, m_base, m_point1, m_point2, m_publicKey,
                m_secretKey, m_useFirst);
        TestUtils.testSerialization(proof, OneOfTwoDlogProof::serialReadIn, PARAMS);
    }
}
