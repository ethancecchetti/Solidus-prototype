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
import org.bouncycastle.jcajce.provider.digest.SHA1;
import org.bouncycastle.jcajce.provider.digest.SHA256;
import org.bouncycastle.jcajce.provider.digest.SHA3;
import org.bouncycastle.math.ec.ECPoint;
import solidus.util.CryptoConstants;
import solidus.util.EncryptionParams;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Random;
import java.util.concurrent.TimeUnit;

public class HashOfECPointsBenchmark {
    private static final int JIT_ITERS = 5000;
    private static final int TESTS = 1;
    private static final int TEST_ITERS = 1000;
    private static final int N_POINTS_TO_HASH = 10;
    private static final ECPoint[] pointToHash = new ECPoint[N_POINTS_TO_HASH];

    public static void main(String[] args) {
        Random rand = new Random();
        EncryptionParams params = EncryptionParams.newTestParams(rand, CryptoConstants.CURVE, CryptoConstants.DIGEST);

        System.out.println("Test various hash strategies...");
        System.out.println("  (warming up the jit, this may take a few seconds)");

        for (int i = 0; i < N_POINTS_TO_HASH; i++) {
            pointToHash[i] = params.getGenerator().multiply(params.getRandomIndex());
        }

        testUnit(params, new SHA3.Digest256());
        testUnit(params, new SHA1.Digest());
        testUnit(params, new SHA256.Digest());
    }

    private static void testUnit(EncryptionParams params, MessageDigest digest) {
        // warm up JIT
        System.out.println("Testing with " + digest.getAlgorithm());
        _runTest(params, digest, JIT_ITERS, false);
        for (int i = 0; i < TESTS; i++) {
            System.out.println("Test " + i + ":");
            _runTest(params, digest, TEST_ITERS, true);
        }
    }

    /*
     * First digest each {@code ECPoint} into an array of 32 bytes, then hash
     * the concatenation of arrays.
     */
    private static BigInteger twice(EncryptionParams params, MessageDigest digest, boolean compress) {
        byte[][] hashes = new byte[N_POINTS_TO_HASH][];
        for (int i = 0; i < pointToHash.length; i++) {
            hashes[i] = digest.digest(pointToHash[i].getEncoded(compress));
        }

        for (byte[] hash : hashes) {
            digest.update(hash);
        }

        return new BigInteger(digest.digest()).mod(params.getGroupSize());
    }

    private static void _runTest(EncryptionParams params, MessageDigest digest, int iters, boolean doPrint) {

        Stopwatch watch = Stopwatch.createUnstarted();
        Stopwatch origWithCompress = Stopwatch.createUnstarted();
        Stopwatch twiceWatch = Stopwatch.createUnstarted();
        Stopwatch twiceCompressWatch = Stopwatch.createUnstarted();
        for (int i = 0; i < iters; i++) {
            // watch.start();
            // byte[][] encodings = new byte[pointToHash.length][];
            // for (int j = 0; j < pointToHash.length; j++)
            // {
            // encodings[j] = pointToHash[j].getEncoded(false);
            // }
            // params.hash(encodings);
            // watch.stop();

            origWithCompress.start();
            params.hash(pointToHash);
            origWithCompress.stop();

            twiceWatch.start();
            twice(params, digest, false);
            twiceWatch.stop();

            twiceCompressWatch.start();
            twice(params, digest, true);
            twiceCompressWatch.stop();
        }

        if (doPrint) {
            System.out.printf("\tOriginal w/o compression: %.2f usec/point\n",
                    (watch.elapsed(TimeUnit.MICROSECONDS) / (double) iters / N_POINTS_TO_HASH));
            System.out.printf("\tOriginal w/ compression\t: %.2f usec/point\n",
                    (origWithCompress.elapsed(TimeUnit.MICROSECONDS) / (double) iters / N_POINTS_TO_HASH));
            System.out.printf("\tTwice w/o compression\t: %.2f usec/point\n",
                    (twiceWatch.elapsed(TimeUnit.MICROSECONDS) / (double) iters / N_POINTS_TO_HASH));
            System.out.printf("\tTwice w/ compression\t: %.2f usec/point\n",
                    (twiceCompressWatch.elapsed(TimeUnit.MICROSECONDS) / (double) iters / N_POINTS_TO_HASH));
        }
    }
}
