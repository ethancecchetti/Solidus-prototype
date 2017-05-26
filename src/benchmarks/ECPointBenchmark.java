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

import java.math.BigInteger;
import java.util.List;
import java.util.Random;
import java.util.concurrent.TimeUnit;

import com.google.common.base.Stopwatch;
import com.google.common.collect.ImmutableList;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;

public class ECPointBenchmark {
    private static final int JIT_ITERS = 10000;
    private static final int TESTS = 10;
    private static final int TEST_ITERS = 20000;

    private static final int NUM_TIMERS = 8;

    private static final int MULTI_INDEX = 0;
    private static final int ADD_INDEX = 1;
    private static final int NORMALIZE_INDEX = 2;
    private static final int RENORMALIZE_INDEX = 3;
    private static final int ENCODE_NORMAL_INDEX = 4;
    private static final int ENCODE_TRUE_INDEX = 5;
    private static final int EQUALS_INDEX = 6;
    private static final int NORMAL_EQUALS_INDEX = 7;

    private static final List<String> CURVE_NAMES = ImmutableList.of(/* "prime192v1", */ "secp128r1", "secp160k1",
            "secp192k1", "secp256k1");

    public static void main(String[] args) {
        for (String curveName : CURVE_NAMES) {
            System.out.println(curveName);

            ECParameterSpec curve = ECNamedCurveTable.getParameterSpec(curveName);
            ECPoint generator = curve.getG();
            BigInteger groupSize = curve.getN();

            // Warm up the JIT
            runTest(generator, groupSize, JIT_ITERS);

            long[] totals = new long[NUM_TIMERS];
            double[][] perMicro = new double[NUM_TIMERS][TESTS];
            for (int testIdx = 0; testIdx < TESTS; testIdx++) {
                long[] testTimes = runTest(generator, groupSize, TEST_ITERS);
                for (int timerIdx = 0; timerIdx < NUM_TIMERS; timerIdx++) {
                    totals[timerIdx] += testTimes[timerIdx];
                    perMicro[timerIdx][testIdx] = TEST_ITERS / (double) testTimes[timerIdx];
                }
            }

            double[] averages = new double[NUM_TIMERS];
            double[] stderr = new double[NUM_TIMERS];
            for (int timerIdx = 0; timerIdx < NUM_TIMERS; timerIdx++) {
                averages[timerIdx] = (TEST_ITERS * TESTS) / (double) totals[timerIdx];
                for (int testIdx = 0; testIdx < TESTS; testIdx++) {
                    stderr[timerIdx] += Math.pow(perMicro[timerIdx][testIdx] - averages[timerIdx], 2);
                }
                stderr[timerIdx] = Math.sqrt(stderr[timerIdx] / TESTS);
            }

            int customEncodingLength = generator.getXCoord().toBigInteger().toByteArray().length
                    + generator.getYCoord().toBigInteger().toByteArray().length;
            for (ECFieldElement elt : generator.getZCoords()) {
                customEncodingLength += elt.toBigInteger().toByteArray().length;
            }
            System.out.printf("  mults/ms: average: %.2f; std error: %.2f\n", (averages[MULTI_INDEX] * 1000.0),
                    (stderr[MULTI_INDEX] * 1000.0));
            System.out.printf("  adds/ms:  average: %.2f; std error: %.2f\n", (averages[ADD_INDEX] * 1000.0),
                    (stderr[ADD_INDEX] * 1000.0));
            System.out.printf("  encoding length: compressed: %d, uncompressed: %d, custom: %d (zcoords: %d/%d)\n",
                    generator.getEncoded(true).length, generator.getEncoded(false).length, customEncodingLength,
                    generator.getZCoords().length, curve.getCurve().getInfinity().getZCoords().length);
            System.out.printf("  normalize/ms:     average: %.2f; std error: %.2f\n",
                    (averages[NORMALIZE_INDEX] * 1000.0), (stderr[NORMALIZE_INDEX] * 1000.0));
            System.out.printf("  renormalize/ms:   average: %.2f; std error: %.2f\n",
                    (averages[RENORMALIZE_INDEX] * 1000.0), (stderr[RENORMALIZE_INDEX] * 1000.0));
            System.out.printf("  encode noraml/ms: average: %.2f; std error: %.2f\n",
                    (averages[ENCODE_NORMAL_INDEX] * 1000.0), (stderr[ENCODE_NORMAL_INDEX] * 1000.0));
            System.out.printf("  encode(true)/ms:  average: %.2f; std error: %.2f\n",
                    (averages[ENCODE_TRUE_INDEX] * 1000.0), (stderr[ENCODE_TRUE_INDEX] * 1000.0));
            System.out.printf("  equals/ms:        average: %.2f; std error: %.2f\n", (averages[EQUALS_INDEX] * 1000.0),
                    (stderr[EQUALS_INDEX] * 1000.0));
            System.out.printf("  norm equals/ms:   average: %.2f; std error: %.2f\n",
                    (averages[NORMAL_EQUALS_INDEX] * 1000.0), (stderr[NORMAL_EQUALS_INDEX] * 1000.0));
        }
    }

    private static long[] runTest(ECPoint generator, BigInteger groupSize, int iterations) {
        Stopwatch multWatch = Stopwatch.createUnstarted();
        Stopwatch addWatch = Stopwatch.createUnstarted();
        Stopwatch normalizeWatch = Stopwatch.createUnstarted();
        Stopwatch renormalizeWatch = Stopwatch.createUnstarted();
        Stopwatch encodeNormalWatch = Stopwatch.createUnstarted();
        Stopwatch encodeTrueWatch = Stopwatch.createUnstarted();
        Stopwatch equalsWatch = Stopwatch.createUnstarted();
        Stopwatch normalEqualsWatch = Stopwatch.createUnstarted();
        Random rand = new Random();

        ECPoint[] points = new ECPoint[] { generator.multiply(new BigInteger(groupSize.bitLength(), rand)),
                generator.multiply(new BigInteger(groupSize.bitLength(), rand)) };
        for (int i = 0; i < iterations; i++) {
            BigInteger r;
            do {
                r = new BigInteger(groupSize.bitLength(), rand);
            } while (r.compareTo(groupSize) >= 0 || r.compareTo(BigInteger.ONE) < 0);

            multWatch.start();
            ECPoint temp = points[i % 2].multiply(r);
            multWatch.stop();

            addWatch.start();
            temp = temp.add(points[1 - (i % 2)]);
            addWatch.stop();

            normalizeWatch.start();
            ECPoint normalizedTemp = temp.normalize();
            normalizeWatch.stop();

            renormalizeWatch.start();
            normalizedTemp.normalize();
            renormalizeWatch.stop();

            encodeNormalWatch.start();
            normalizedTemp.getEncoded(true);
            encodeNormalWatch.stop();

            encodeTrueWatch.start();
            temp.getEncoded(true);
            encodeTrueWatch.stop();

            equalsWatch.start();
            points[0].equals(points[1]);
            equalsWatch.stop();

            ECPoint normTemp2 = temp.normalize();
            normalEqualsWatch.start();
            normalizedTemp.equals(normTemp2);
            normalEqualsWatch.stop();
            // ECPoint normP0 = points[0].normalize();
            // ECPoint normP1 = points[1].normalize();
            // normalEqualsWatch.start();
            // normP0.equals(normP1);
            // normalEqualsWatch.stop();

            points[i % 2] = temp;
        }

        long[] times = new long[NUM_TIMERS];
        times[MULTI_INDEX] = multWatch.elapsed(TimeUnit.MICROSECONDS);
        times[ADD_INDEX] = addWatch.elapsed(TimeUnit.MICROSECONDS);
        times[NORMALIZE_INDEX] = normalizeWatch.elapsed(TimeUnit.MICROSECONDS);
        times[RENORMALIZE_INDEX] = renormalizeWatch.elapsed(TimeUnit.MICROSECONDS);
        times[ENCODE_NORMAL_INDEX] = encodeNormalWatch.elapsed(TimeUnit.MICROSECONDS);
        times[ENCODE_TRUE_INDEX] = encodeTrueWatch.elapsed(TimeUnit.MICROSECONDS);
        times[EQUALS_INDEX] = equalsWatch.elapsed(TimeUnit.MICROSECONDS);
        times[NORMAL_EQUALS_INDEX] = normalEqualsWatch.elapsed(TimeUnit.MICROSECONDS);
        return times;
    }
}
