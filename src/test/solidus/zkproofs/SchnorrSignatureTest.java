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

import org.bouncycastle.math.ec.ECPoint;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.theories.DataPoint;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

import solidus.util.CryptoConstants;
import solidus.util.EncryptionParams;
import solidus.zkproofs.SchnorrSignature;

import test.util.TestUtils;

import java.math.BigInteger;
import java.util.Random;

/**
 * Test suite for SchnorrSignature.
 *
 * @author fanz@cs.cornell.edu
 */

@RunWith(Theories.class)
public class SchnorrSignatureTest {
    private static final int MESSAGE_LENGTH = 1000;
    private static final EncryptionParams PARAMS = EncryptionParams.newTestParams(new Random(TestUtils.RANDOM_SEED),
            CryptoConstants.CURVE, CryptoConstants.DIGEST);

    private static final BigInteger SIGN_KEY = new BigInteger(
            "7bf0160c5a4fc3e505aae48d494f0f1a2f8e95ca9977dfcf454a2c3ac09744c1", 16);
    private static final BigInteger OTHER_SIGN_KEY = new BigInteger(
            "52a8573d012a3b84eb254d21828799af2ecaacfb37cb564aadaec9e3fda8c8dc", 16);

    @DataPoint
    public static final ECPoint VER_KEY = PARAMS.getGenerator().multiply(SIGN_KEY);
    @DataPoint
    public static final ECPoint OTHER_VER_KEY = PARAMS.getGenerator().multiply(OTHER_SIGN_KEY);

    @DataPoint
    public static final byte[] MSG1 = new byte[MESSAGE_LENGTH];
    @DataPoint
    public static final byte[] MSG2 = new byte[MESSAGE_LENGTH];

    @BeforeClass
    public static void initMessages() {
        PARAMS.getRandomSource().nextBytes(MSG1);
        MSG2[0] = (byte) (MSG1[0] ^ 0xff);
        System.arraycopy(MSG1, 1, MSG2, 1, MESSAGE_LENGTH - 1);
    }

    @Theory
    public void testVerification(ECPoint verKey, byte[] message) {
        SchnorrSignature sig = SchnorrSignature.sign(PARAMS, SIGN_KEY, MSG1);

        Assert.assertEquals((verKey == VER_KEY && message == MSG1), sig.verify(verKey, message));
    }

    @Test
    public void testSerialization() {
        TestUtils.testSerialization(SchnorrSignature.sign(PARAMS, SIGN_KEY, MSG1), SchnorrSignature::serialReadIn,
                PARAMS);
    }
}
