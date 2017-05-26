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

package benchmarks.aws;

import com.google.common.base.Stopwatch;
import com.google.common.collect.ImmutableList;
import org.bouncycastle.crypto.ec.ECPair;
import org.bouncycastle.math.ec.ECPoint;

import solidus.state.pvorm.EncryptedPvorm;
import solidus.state.pvorm.OwnedPvorm;
import solidus.state.pvorm.PvormUpdate;
import solidus.util.CryptoConstants;
import solidus.util.EncryptionParams;
import solidus.util.Encryptor;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.TimeUnit;
import java.util.stream.IntStream;
import java.util.stream.LongStream;
import java.util.stream.Stream;

public class UserScalingBenchmark {
    private static final int JIT_ITERS = 500;
    private static final int TESTS = 10;
    private static final int TEST_ITERS = 500;

    private enum Watch {
        UPDATE, GENERATION, VERIFICATION, SERIALIZATION, DESERIALIZATION
    }

    public static void main(String[] args) throws InterruptedException {
        int LOG_MAX_BALANCE = 30;
        int[] TREE_DEPTH_RANGE = IntStream.range(10, 22 + 1).toArray();

        EncryptionParams.Builder paramsBuilder = new EncryptionParams.Builder(new Random(1), // CryptoConstants.buildTestPrng(1234567890),
                CryptoConstants.CURVE, CryptoConstants.DIGEST).normalizePoints().setCompressSerializedPoints(true)
                        .setMaxDiscreteLog(1L << LOG_MAX_BALANCE).setLookupTableGap(1 << (LOG_MAX_BALANCE - 10));

        BigInteger secretKey = null;
        ECPoint publicKey = null;
        if (args.length > 1) {
            Path filePath = Paths.get(args[0]);
            secretKey = new BigInteger(args[1]);
            publicKey = CryptoConstants.CURVE.getG().multiply(secretKey).normalize();
            paramsBuilder.addKeyToEncryptionFile(publicKey, filePath);

            System.out.println("Pulling encryptions from file: " + filePath);
        } else {
            paramsBuilder.useFastTestEncryptor();
        }
        EncryptionParams params = paramsBuilder.forTesting().build();
        // Pre-start encryptor so we can get some values computed in the
        // background.
        if (secretKey == null) {
            secretKey = params.getRandomIndex();
            publicKey = params.getGenerator().multiply(secretKey).normalize();
        }
        params.getEncryptor(publicKey);

        for (int treeDepth : TREE_DEPTH_RANGE) {
            int ORAM_ELTS = (1 << treeDepth);
            List<ECPoint> keys = _buildKeyList(ORAM_ELTS, params);
            run(params, keys, secretKey, treeDepth, 3, 25);
        }
    }

    private static void run(EncryptionParams params, List<ECPoint> keys, BigInteger secretKey, int treeDepth,
            int bucketSize, int stashSize) throws InterruptedException {
        System.out.println("# Building oram");
        Stopwatch buildWatch = Stopwatch.createStarted();

        OwnedPvorm.Builder oramBuilder = new OwnedPvorm.Builder(params, secretKey, treeDepth, bucketSize, stashSize);
        System.out.println("#   constructed frame, now adding " + keys.size() + " keys");
        for (ECPoint key : keys) {
            oramBuilder.insert(key, 0);
        }
        System.out.println("#   keys inserted, now building");
        OwnedPvorm oram = oramBuilder.build();
        EncryptedPvorm duplicateOram = oram.getEncryptedPvorm().duplicate();

        buildWatch.stop();
        System.out.println("# Oram built and duplicated in " + buildWatch + ". Now warming up JIT.");

        _runBenchmark(params, oram, duplicateOram, keys, 1, JIT_ITERS, false);

        System.out.println("# JIT is warm (hopefully)");

        System.out.printf("# Testing with TreeDepth=%d, BucketSize=%d, StashSize=%d\n", treeDepth, bucketSize,
                stashSize);
        String result = _runBenchmark(params, oram, duplicateOram, keys, TESTS, TEST_ITERS, true);

        System.out.printf("%d %d %s\n", bucketSize, stashSize, result);
    }

    private static List<ECPoint> _buildKeyList(int size, EncryptionParams params) {
        ImmutableList.Builder<ECPoint> keysBuilder = new ImmutableList.Builder<>();
        ECPoint lastKey = params.getInfinity();
        for (int i = 0; i < size; i++) {
            lastKey = lastKey.add(params.getGenerator());
            keysBuilder.add(lastKey);
        }
        return keysBuilder.build();
    }

    private static String _runBenchmark(EncryptionParams params, OwnedPvorm oram, EncryptedPvorm duplicateOram,
            List<ECPoint> keys, int rounds, int iterations, boolean doPrint) {
        Encryptor encryptor = params.getEncryptor(oram.getPublicKey());
        ECPair encryptedZero = encryptor.encryptBalance(0);

        Map<Watch, long[]> times = new EnumMap<>(Watch.class);
        Map<Watch, Long> totals = new EnumMap<>(Watch.class);
        for (Watch watch : Watch.values()) {
            times.put(watch, new long[rounds]);
            totals.put(watch, 0L);
        }

        ProgressBar progressBar = new ProgressBar();
        if (rounds > 0) progressBar.update(0, rounds);
        for (int i = 0; i < rounds; i++) {
            Map<Watch, Stopwatch> watchMap = new EnumMap<>(Watch.class);
            for (Watch watch : Watch.values())
                watchMap.put(watch, Stopwatch.createUnstarted());

            for (int j = 0; j < iterations; j++) {
                ECPair encryptedKey = encryptor.encryptPoint(keys.get(i % keys.size()));

                watchMap.get(Watch.GENERATION).start();
                PvormUpdate update = oram.update(encryptedKey, encryptedZero, true, null);
                watchMap.get(Watch.GENERATION).stop();

                try {
                    ByteArrayOutputStream byteOutStream = new ByteArrayOutputStream();

                    watchMap.get(Watch.SERIALIZATION).start();
                    update.serialWriteOut(byteOutStream, params.compressSerializedPoints());
                    watchMap.get(Watch.SERIALIZATION).stop();

                    byte[] serializedUpdate = byteOutStream.toByteArray();
                    if (i == 0 && j == 0 && doPrint) {
                        System.out.println("# Size of serialized PublicOramUpdate: " + serializedUpdate.length);
                    }
                    ByteArrayInputStream byteInStream = new ByteArrayInputStream(serializedUpdate);

                    watchMap.get(Watch.DESERIALIZATION).start();
                    PvormUpdate.serialReadIn(byteInStream, params);
                    watchMap.get(Watch.DESERIALIZATION).stop();
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }

                watchMap.get(Watch.VERIFICATION).start();
                if (!duplicateOram.verifyUpdate(update, null)) {
                    throw new RuntimeException("update failed to verify!");
                }
                watchMap.get(Watch.VERIFICATION).stop();
                duplicateOram.applyLastVerifiedUpdate();
            }

            for (Watch watch : Watch.values()) {
                long timeElapsed = watchMap.get(watch).elapsed(TimeUnit.MILLISECONDS);
                times.get(watch)[i] = timeElapsed;
                totals.put(watch, totals.get(watch) + timeElapsed);
            }

            progressBar.update(i, rounds);
        }

        Map<Watch, Double> averages = new EnumMap<>(Watch.class);
        Map<Watch, Double> stdErrs = new EnumMap<>(Watch.class);
        for (Watch watch : Watch.values()) {
            averages.put(watch, (double) totals.get(watch) / (rounds * iterations));
            double stdErr = 0.0;
            for (int i = 0; i < rounds; i++) {
                stdErr += Math.pow(((double) times.get(watch)[i] / iterations) - averages.get(watch), 2);
            }
            stdErrs.put(watch, Math.sqrt(stdErr / rounds));
        }

        if (doPrint) {
            System.out.printf("# Benchmark ran for %d rounds with %d iterations in each round.\n", rounds, iterations);
            int textLength = Stream.of(Watch.values()).map(Watch::name).mapToInt(String::length).max().getAsInt();
            for (Watch watch : Watch.values()) {
                long max = LongStream.of(times.get(watch)).max().getAsLong();
                long min = LongStream.of(times.get(watch)).min().getAsLong();
                System.out.printf("#  %" + textLength + "s: avg %.2fms; stderr %.2f; max: %d; min: %d\n",
                        watch.name().toLowerCase(), averages.get(watch), stdErrs.get(watch), max, min);
            }

            return String.format("%.2f %.2f %.2f %.2f", averages.get(Watch.GENERATION),
                    averages.get(Watch.VERIFICATION), stdErrs.get(Watch.GENERATION), stdErrs.get(Watch.VERIFICATION));
        }

        return null;
    }
}
