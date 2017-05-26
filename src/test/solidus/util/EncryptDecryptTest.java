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

package test.solidus.util;

import java.math.BigInteger;
import java.util.Random;
import java.util.stream.IntStream;

import org.bouncycastle.crypto.ec.ECPair;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.Rule;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;

import solidus.util.CryptoConstants;
import solidus.util.Decryptor;
import solidus.util.EncryptionParams;
import solidus.util.Encryptor;

import test.util.TestUtils;

@RunWith(Theories.class)
public class EncryptDecryptTest {
    private static final BigInteger SECRET_KEY = new BigInteger(
            "2afe91f84df247fa7e52ba800c9980de0335ec9849a28f2d462080129899cb11", 16);
    private static final ECPoint PUBLIC_KEY = CryptoConstants.CURVE.getG().multiply(SECRET_KEY).normalize();

    private static final int MAX_BALANCE = 128;

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @DataPoints("table gap")
    public static final int[] ALL_TABLE_GAPS = new int[] { 1, 3 };

    @DataPoints("good balances")
    public static final long[] GOOD_BALANCES = new long[] { -MAX_BALANCE, -MAX_BALANCE + 1, -MAX_BALANCE / 2, -2, -1, 0,
            1, 2, MAX_BALANCE / 2, MAX_BALANCE, MAX_BALANCE };

    @DataPoints
    public static final BigInteger[] BAD_BALANCES = new BigInteger[] { BigInteger.valueOf(-MAX_BALANCE * 2),
            BigInteger.valueOf(-MAX_BALANCE - IntStream.of(ALL_TABLE_GAPS).max().getAsInt()),
            BigInteger.valueOf(MAX_BALANCE + 1), BigInteger.valueOf(MAX_BALANCE * 2),
            // Also test two random very large values.
            // We won't try to encrypt these as
            // balances, but we will try to decrypt.
            new BigInteger("269f692585502513dba2bb95aa33d840fed53dd9fa820f2726fc3331bd91fe13", 16),
            new BigInteger("3aafbb7b3309a86a3a80f4ee9d926fcd3f5626b9466a030b9f208e6076cd14fb", 16) };

    private EncryptionParams _buildParams(int tableGap, boolean normalize, boolean blind) {
        EncryptionParams.Builder paramsBuilder = new EncryptionParams.Builder(new Random(TestUtils.RANDOM_SEED),
                CryptoConstants.CURVE, CryptoConstants.DIGEST).setMaxDiscreteLog(MAX_BALANCE)
                        .setLookupTableGap(tableGap).forTesting();
        if (normalize) paramsBuilder.normalizePoints();
        if (blind) paramsBuilder.blindDecryption();

        return paramsBuilder.build();
    }

    @Theory
    public void testEncryptionDecryption(int tableGap, boolean normalize, boolean blind, long balance) {
        EncryptionParams params = _buildParams(tableGap, normalize, blind);
        Encryptor encryptor = params.getEncryptor(PUBLIC_KEY);
        Decryptor decryptor = params.getDecryptor(SECRET_KEY);

        ECPair encryption = encryptor.encryptBalance(balance);
        ECPair reencryption = encryptor.reencrypt(encryption);
        long decBalance = decryptor.decryptBalance(encryption);
        long reencBalance = decryptor.decryptBalance(reencryption);

        Assert.assertEquals(balance, decBalance);
        Assert.assertEquals(balance, reencBalance);

        ECPoint expectedPoint = params.getGenerator().multiply(BigInteger.valueOf(balance));
        Assert.assertEquals(expectedPoint, decryptor.decryptPoint(encryption));
        Assert.assertEquals(expectedPoint, decryptor.decryptPoint(reencryption));
    }

    @Theory
    public void testPointDecryption(int tableGap, boolean normalize, boolean blind, BigInteger balance) {
        EncryptionParams params = _buildParams(tableGap, normalize, blind);
        Encryptor encryptor = params.getEncryptor(PUBLIC_KEY);
        Decryptor decryptor = params.getDecryptor(SECRET_KEY);

        ECPoint point = params.getGenerator().multiply(balance);

        ECPair valEnc = encryptor.encryptValue(balance);
        ECPair pointEnc = encryptor.encryptPoint(point);
        ECPair reencryption = encryptor.reencrypt(pointEnc);

        Assert.assertEquals(point, decryptor.decryptPoint(valEnc));
        Assert.assertEquals(point, decryptor.decryptPoint(pointEnc));
        Assert.assertEquals(point, decryptor.decryptPoint(reencryption));
    }

    @Theory
    public void testInvalidEncryption(int tableGap, boolean normalize, boolean blind, BigInteger balance) {
        // We're trying to encrypt as balances, so skip anything that can't
        // even be represented as a long.
        Assume.assumeTrue(balance.compareTo(BigInteger.valueOf(Long.MAX_VALUE)) < 0);
        thrown.expect(IllegalArgumentException.class);

        EncryptionParams params = _buildParams(tableGap, normalize, blind);
        params.getEncryptor(PUBLIC_KEY).encryptBalance(balance.longValue());
    }

    @Theory
    public void testInvalidDecryption(int tableGap, boolean normalize, boolean blind, BigInteger balance) {
        thrown.expect(IllegalArgumentException.class);

        EncryptionParams params = _buildParams(tableGap, normalize, blind);
        ECPair enc = params.getEncryptor(PUBLIC_KEY).encryptValue(balance);
        params.getDecryptor(SECRET_KEY).decryptBalance(enc);
    }
}
