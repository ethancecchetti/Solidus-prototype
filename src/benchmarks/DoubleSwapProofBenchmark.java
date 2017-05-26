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

package benchmarks;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.concurrent.TimeUnit;

import org.bouncycastle.crypto.ec.ECPair;
import org.bouncycastle.math.ec.ECPoint;

import com.google.common.base.Stopwatch;

import solidus.util.CryptoConstants;
import solidus.util.EncryptionParams;
import solidus.util.Encryptor;
import solidus.zkproofs.DoubleSwapProof;

public class DoubleSwapProofBenchmark {
    private static final int JIT_ITERS = 5000;
    private static final int TESTS = 5;
    private static final int TEST_ITERS = 10000;

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

    public static void main(String[] args) {
        EncryptionParams params = new EncryptionParams.Builder(CryptoConstants.buildPrng(), CryptoConstants.CURVE,
                CryptoConstants.DIGEST).normalizePoints().forTesting().build();

        System.out.println("Starting DoubleSwapProofBenchmark");
        System.out.println("  (warming up the jit, this may take a few seconds)");

        _runTest(params, JIT_ITERS, false);

        for (int i = 0; i < TESTS; i++) {
            System.out.println("Test " + i + ":");
            _runTest(params, TEST_ITERS, true);
        }
    }

    private static void _runTest(EncryptionParams params, int iters, boolean doPrint) {
        Stopwatch reEncWatch = Stopwatch.createUnstarted();
        Stopwatch swapperWatch = Stopwatch.createUnstarted();
        Stopwatch verifierWatch = Stopwatch.createUnstarted();

        BigInteger secretKey = params.getRandomIndex();
        ECPoint publicKey = params.getGenerator().multiply(secretKey).normalize();
        Encryptor encryptor = params.getEncryptor(publicKey);

        for (int i = 0; i < iters; i++) {
            ECPair initCipher1 = encryptor.encryptValue(params.getRandomIndex());
            ECPair initCipher2 = encryptor.encryptValue(params.getRandomIndex());
            ECPair initCipher3 = encryptor.encryptValue(params.getRandomIndex());
            ECPair initCipher4 = encryptor.encryptValue(params.getRandomIndex());

            reEncWatch.start();
            ECPair reCipher1 = encryptor.reencrypt(initCipher1);
            ECPair reCipher2 = encryptor.reencrypt(initCipher2);
            ECPair reCipher3 = encryptor.reencrypt(initCipher3);
            ECPair reCipher4 = encryptor.reencrypt(initCipher4);
            reEncWatch.stop();

            Pair preSwap1 = new Pair(initCipher1, initCipher2);
            Pair preSwap2 = new Pair(initCipher3, initCipher4);
            Pair postSwap1 = new Pair(reCipher1, reCipher2);
            Pair postSwap2 = new Pair(reCipher3, reCipher4);

            swapperWatch.start();
            DoubleSwapProof swapProof = DoubleSwapProof.fromFakeSwap(params, preSwap1, preSwap2, postSwap1, postSwap2,
                    publicKey, secretKey);
            swapperWatch.stop();

            verifierWatch.start();
            swapProof.verify(preSwap1, preSwap2, postSwap1, postSwap2, publicKey);
            verifierWatch.stop();
        }

        if (doPrint) {
            System.out.println("  usec/reEnc:  " + (reEncWatch.elapsed(TimeUnit.MICROSECONDS) / (double) iters));
            System.out.println("  usec/swap:   " + (swapperWatch.elapsed(TimeUnit.MICROSECONDS) / (double) iters));
            System.out.println("  usec/verify: " + (verifierWatch.elapsed(TimeUnit.MICROSECONDS) / (double) iters));
        }
    }
}
