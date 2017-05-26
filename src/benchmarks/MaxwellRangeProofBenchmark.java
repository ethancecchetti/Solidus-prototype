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

import com.google.common.base.Stopwatch;

import org.bouncycastle.crypto.ec.ECPair;
import org.bouncycastle.math.ec.ECPoint;
import solidus.util.CryptoConstants;
import solidus.util.DaemonThreadFactory;
import solidus.util.EncryptionParams;
import solidus.util.Encryptor;
import solidus.zkproofs.MaxwellRangeProof;

import java.math.BigInteger;
import java.util.Random;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class MaxwellRangeProofBenchmark {
    private static final int EXECUTION_THREADS = 8;
    private static final int MAX_BIT_LENGTH = 32;
    private static final int JIT_ITERS = 200;
    private static final int TESTS = 1;
    private static final int TEST_ITERS = 200;

    public static void main(String[] args) {
        EncryptionParams params = new EncryptionParams.Builder(new Random(1), CryptoConstants.CURVE,
                CryptoConstants.DIGEST).normalizePoints().setMaxDiscreteLog((1L << MAX_BIT_LENGTH) - 1)
                        .setLookupTableGap(1 << (MAX_BIT_LENGTH - 10)).forTesting().build();

        System.out.println("Starting MaxwellRangeProof Benchmark");
        System.out.println("  (warming up the jit, this may take a few seconds)");

        _runTest(params, JIT_ITERS, false, null);

        ExecutorService executor = (EXECUTION_THREADS > 0
                ? Executors.newFixedThreadPool(EXECUTION_THREADS, new DaemonThreadFactory("ProofThread")) : null);

        for (int i = 0; i < TESTS; i++) {
            System.out.println("Test " + i + ":");
            _runTest(params, TEST_ITERS, true, executor);
        }
    }

    private static void _runTest(EncryptionParams params, int iters, boolean doPrint, ExecutorService executor) {

        Stopwatch proveWatch = Stopwatch.createUnstarted();
        Stopwatch verifyWatch = Stopwatch.createUnstarted();

        BigInteger secretKey = params.getRandomIndex();
        ECPoint publicKey = params.getGenerator().multiply(secretKey).normalize();

        for (int i = 0; i < iters; i++) {
            Encryptor encryptor = params.getEncryptor(publicKey);
            long v = new BigInteger(params.getMaxDiscreteLogBits(), params.getRandomSource()).longValue();

            proveWatch.start();
            ECPair balanceCipher = encryptor.encryptBalance(v);
            MaxwellRangeProof rangeProof = MaxwellRangeProof.buildProof(params, balanceCipher, v, publicKey, secretKey,
                    executor);
            proveWatch.stop();

            verifyWatch.start();
            if (!rangeProof.verify(balanceCipher, publicKey, executor)) {
                System.out.println("Error!");
            }

            verifyWatch.stop();
        }

        if (doPrint) {
            System.out.printf("  msec/prove:  %.2f\n", (proveWatch.elapsed(TimeUnit.MILLISECONDS) / (double) iters));
            System.out.printf("  msec/verify: %.2f\n", (verifyWatch.elapsed(TimeUnit.MILLISECONDS) / (double) iters));
        }
    }
}
