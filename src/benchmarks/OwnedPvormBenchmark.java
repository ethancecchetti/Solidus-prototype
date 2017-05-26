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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.stream.LongStream;
import java.util.stream.Stream;

import com.google.common.base.Stopwatch;
import com.google.common.collect.ImmutableList;

import org.bouncycastle.crypto.ec.ECPair;
import org.bouncycastle.math.ec.ECPoint;

import solidus.state.pvorm.EncryptedPvorm;
import solidus.state.pvorm.OwnedPvorm;
import solidus.state.pvorm.PvormUpdate;
import solidus.util.CryptoConstants;
import solidus.util.DaemonThreadFactory;
import solidus.util.EncryptionParams;
import solidus.util.Encryptor;

public class OwnedPvormBenchmark {
    private static final int JIT_ITERS = 200;
    private static final int TEST_ITERS = 2000;

    private static final int MAX_BALANCE = 1 << 15;
    private static final int MAX_DISCRETE_LOG_BITS = 30;

    private static final int TREE_DEPTH = 15;
    private static final int BUCKET_SIZE = 3;
    private static final int STASH_SIZE = 25;
    private static final int PVORM_ELTS = (1 << TREE_DEPTH);

    private static enum Watch {
        UPDATE, GENERATION, VERIFICATION, SERIALIZATION, DESERIALIZATION;
    }

    // private static final int ENCRYPTOR_THREADS = 1;
    // private static final int ENCRYPTOR_QUEUE_SIZE = 100000;
    private static final List<Integer> PROOF_THREADS = ImmutableList.of(1, 2, 4, 6, 8, 10); // ,
                                                                                            // 16,
                                                                                            // 32,
                                                                                            // 35,
                                                                                            // 36,
                                                                                            // 37);

    public static void main(String[] args) throws InterruptedException {
        EncryptionParams.Builder paramsBuilder = new EncryptionParams.Builder(new Random(1), // CryptoConstants.buildTestPrng(1234567890),
                CryptoConstants.CURVE, CryptoConstants.DIGEST).normalizePoints().setCompressSerializedPoints(true)
                        // .setEncryptorThreads(ENCRYPTOR_THREADS)
                        // .setEncryptorQueueSize(ENCRYPTOR_QUEUE_SIZE)
                        .setMaxDiscreteLog(MAX_BALANCE).setMaxDiscreteLogBits(MAX_DISCRETE_LOG_BITS);

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

        List<ECPoint> keys = _buildKeyList(PVORM_ELTS, params);

        // Pre-start encryptor so we can get some values computed in the
        // background.
        if (secretKey == null) {
            secretKey = params.getRandomIndex();
            publicKey = params.getGenerator().multiply(secretKey).normalize();
        }
        params.getEncryptor(publicKey);

        System.out.println("# Building PVORM");
        Stopwatch buildWatch = Stopwatch.createStarted();

        OwnedPvorm.Builder pvormBuilder = new OwnedPvorm.Builder(params, secretKey, TREE_DEPTH, BUCKET_SIZE,
                STASH_SIZE);
        System.out.println("#   constructed frame, now adding " + keys.size() + " keys");
        for (ECPoint key : keys) {
            pvormBuilder.insert(key, 0);
        }
        System.out.println("#   keys inserted, now building");
        OwnedPvorm pvorm = pvormBuilder.build();
        EncryptedPvorm duplicatePvorm = pvorm.getEncryptedPvorm().duplicate();

        buildWatch.stop();
        System.out.println("# PVORM built and duplicated in " + buildWatch + ". Now warming up JIT.");

        _runBenchmark(params, pvorm, duplicatePvorm, keys, null, 0, JIT_ITERS, false);

        System.out.println("# JIT is warm (hopefully)");

        for (int threadCount : PROOF_THREADS) {
            System.out.printf("\n# Test with %d threads.\n", threadCount);

            ExecutorService executor = (threadCount == 0 ? null
                    : Executors.newFixedThreadPool(threadCount, new DaemonThreadFactory("ProofThread")));
            _runBenchmark(params, pvorm, duplicatePvorm, keys, executor, threadCount, TEST_ITERS, true);

            if (executor != null) {
                executor.shutdown();
                try {
                    if (!executor.awaitTermination(10, TimeUnit.SECONDS)) {
                        throw new RuntimeException("Executor shutdown timed out on " + threadCount + " thread test");
                    }
                } catch (InterruptedException e) {
                    System.err.println("Executor shutdown interrupted on " + threadCount + " thread test");
                    throw e;
                }
            }
        }
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

    private static void _runBenchmark(EncryptionParams params, OwnedPvorm pvorm, EncryptedPvorm duplicatePvorm,
            List<ECPoint> keys, ExecutorService executor, int numThreads, int iterations, boolean doPrint) {
        Encryptor encryptor = params.getEncryptor(pvorm.getPublicKey());
        ECPair encryptedZero = encryptor.encryptBalance(0);

        Map<Watch, long[]> times = new EnumMap<>(Watch.class);
        Map<Watch, Long> totals = new EnumMap<>(Watch.class);
        for (Watch watch : Watch.values()) {
            times.put(watch, new long[iterations]);
            totals.put(watch, 0L);
        }

        Map<Watch, Stopwatch> watchMap = new EnumMap<>(Watch.class);
        for (Watch watch : Watch.values())
            watchMap.put(watch, Stopwatch.createUnstarted());

        for (int i = 0; i < iterations; i++) {
            for (Watch watch : Watch.values())
                watchMap.get(watch).reset();

            ECPair encryptedKey = encryptor.encryptPoint(keys.get(i % keys.size()));

            watchMap.get(Watch.GENERATION).start();
            PvormUpdate update = pvorm.update(encryptedKey, encryptedZero, true, executor);
            watchMap.get(Watch.GENERATION).stop();

            try {
                ByteArrayOutputStream byteOutStream = new ByteArrayOutputStream();

                watchMap.get(Watch.SERIALIZATION).start();
                update.serialWriteOut(byteOutStream, params.compressSerializedPoints());
                watchMap.get(Watch.SERIALIZATION).stop();

                byte[] serializedUpdate = byteOutStream.toByteArray();
                if (i == 0 && doPrint) {
                    System.out.println("# Size of serialized PvormUpdate: " + serializedUpdate.length);
                }
                ByteArrayInputStream byteInStream = new ByteArrayInputStream(serializedUpdate);

                watchMap.get(Watch.DESERIALIZATION).start();
                PvormUpdate.serialReadIn(byteInStream, params);
                watchMap.get(Watch.DESERIALIZATION).stop();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }

            watchMap.get(Watch.VERIFICATION).start();
            if (!duplicatePvorm.verifyUpdate(update, executor)) {
                throw new RuntimeException("update failed to verify!");
            }
            watchMap.get(Watch.VERIFICATION).stop();
            duplicatePvorm.applyLastVerifiedUpdate();

            for (Watch watch : Watch.values()) {
                long timeElapsed = watchMap.get(watch).elapsed(TimeUnit.MILLISECONDS);
                times.get(watch)[i] = timeElapsed;
                totals.put(watch, totals.get(watch) + timeElapsed);
            }
        }

        Map<Watch, Double> averages = new EnumMap<>(Watch.class);
        Map<Watch, Double> stdErrs = new EnumMap<>(Watch.class);
        for (Watch watch : Watch.values()) {
            averages.put(watch, (double) totals.get(watch) / iterations);
            double stdErr = 0.0;
            for (int i = 0; i < iterations; i++) {
                stdErr += Math.pow((times.get(watch)[i]) - averages.get(watch), 2);
            }
            stdErrs.put(watch, Math.sqrt(stdErr / iterations));
        }

        if (doPrint) {
            int textLength = Stream.of(Watch.values()).map(Watch::name).mapToInt(String::length).max().getAsInt();

            for (Watch watch : Watch.values()) {
                long max = LongStream.of(times.get(watch)).max().getAsLong();
                long min = LongStream.of(times.get(watch)).min().getAsLong();
                System.out.printf("#  %" + textLength + "s: avg %.2fms; stderr %.2f; max: %d; min: %d\n",
                        watch.name().toLowerCase(), averages.get(watch), stdErrs.get(watch), max, min);
            }

            System.out.printf("%d %.2f %.2f %.2f %.2f\n", numThreads, averages.get(Watch.GENERATION),
                    averages.get(Watch.VERIFICATION), stdErrs.get(Watch.GENERATION), stdErrs.get(Watch.VERIFICATION));
        }
    }
}
