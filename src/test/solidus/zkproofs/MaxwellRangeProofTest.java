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
import java.util.Random;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import org.bouncycastle.crypto.ec.ECPair;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

import solidus.util.CryptoConstants;
import solidus.util.EncryptionParams;
import solidus.zkproofs.MaxwellRangeProof;

import test.util.TestUtils;

@RunWith(Theories.class)
public class MaxwellRangeProofTest {
    private static final BigInteger SECRET_KEY = new BigInteger(
            "156c87c0d80a3c2bb3059b4fd2615cbc6d006410fd8f384831bf47cbd938e5bf", 16);
    private static final ECPoint PUBLIC_KEY = CryptoConstants.CURVE.getG().multiply(SECRET_KEY);

    private static final ECPoint OTHER_PKEY = CryptoConstants.CURVE.getG()
            .multiply(new BigInteger("68d1466d498a2614065d5479e3b4be3e11060727d91f44d75a14416a6452e116", 16));

    private static final int THREAD_COUNT = 2;

    @DataPoints
    public static final int[] DISCRETE_LOG_BITS = new int[] { 2, 10 };

    @DataPoints
    public static final long[] VALUES = new long[] { 0, 1, 3, 4, 5, 512, 1023, 1024, 1025, Long.MAX_VALUE, -1, -3,
            Long.MIN_VALUE };

    private EncryptionParams _buildParams(int maxDiscreteLogBits) {
        return new EncryptionParams.Builder(new Random(TestUtils.RANDOM_SEED), CryptoConstants.CURVE,
                CryptoConstants.DIGEST).setMaxDiscreteLog((1 << maxDiscreteLogBits) - 1)
                        .setLookupTableGap(1 << (maxDiscreteLogBits - 1)).forTesting().build();
    }

    @Theory
    public void testValidProofs(int maxDiscreteLogBits, long value, boolean threaded) throws InterruptedException {
        Assume.assumeTrue(value >= 0 && value < (1L << maxDiscreteLogBits));

        ExecutorService executor = (threaded ? Executors.newFixedThreadPool(THREAD_COUNT) : null);
        EncryptionParams params = _buildParams(maxDiscreteLogBits);
        ECPair cipher = params.getEncryptor(PUBLIC_KEY).encryptBalance(value);
        ECPair otherCipher = params.getEncryptor(PUBLIC_KEY).encryptBalance(value);
        ECPair diffKeyCipher = params.getEncryptor(OTHER_PKEY).encryptBalance(value);

        MaxwellRangeProof rangeProof = MaxwellRangeProof.buildProof(params, cipher, value, PUBLIC_KEY, SECRET_KEY,
                executor);
        Assert.assertTrue(rangeProof.verify(cipher, PUBLIC_KEY, executor));
        Assert.assertFalse(rangeProof.verify(cipher, OTHER_PKEY, executor));
        Assert.assertFalse(rangeProof.verify(otherCipher, PUBLIC_KEY, executor));
        Assert.assertFalse(rangeProof.verify(diffKeyCipher, PUBLIC_KEY, executor));
        Assert.assertFalse(rangeProof.verify(diffKeyCipher, OTHER_PKEY, executor));

        if (threaded) {
            executor.shutdown();
            Assert.assertTrue(executor.awaitTermination(1, TimeUnit.SECONDS));
        }
    }

    @Theory
    public void testInvalidBalances(int maxDiscreteLogBits, long value) {
        Assume.assumeFalse(value >= 0 && value < (1L << maxDiscreteLogBits));

        EncryptionParams params = _buildParams(maxDiscreteLogBits);
        ECPair cipher = params.getEncryptor(PUBLIC_KEY).encryptValue(BigInteger.valueOf(value));

        MaxwellRangeProof rangeProof = MaxwellRangeProof.buildProof(params, cipher, value, PUBLIC_KEY, SECRET_KEY);
        Assert.assertFalse(rangeProof.verify(cipher, PUBLIC_KEY));
    }

    @Theory
    public void testSerialization(int maxDiscreteLogBits, long value) {
        EncryptionParams params = _buildParams(maxDiscreteLogBits);
        ECPair cipher = params.getEncryptor(PUBLIC_KEY).encryptValue(BigInteger.valueOf(value));
        MaxwellRangeProof rangeProof = MaxwellRangeProof.buildProof(params, cipher, value, PUBLIC_KEY, SECRET_KEY);
        TestUtils.testSerialization(rangeProof, MaxwellRangeProof::serialReadIn, params);
    }
}
