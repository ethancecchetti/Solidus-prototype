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
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import com.google.common.base.Stopwatch;
import com.google.common.collect.ImmutableList;

import solidus.util.CryptoConstants;
import solidus.util.EncryptionParams;

public class ParallelECBenchmark {
    private static final int NUMBER_OF_MULTS = 100000;
    private static final int QUEUE_SIZE = 10000;
    private static final BigInteger QUEUE_EMPTY_FACTOR = BigInteger.valueOf(-1);
    private static final List<Integer> THREADS = ImmutableList.of(1, 2, 4, 8, 16, 32, 64, 128);

    public static void main(String[] args) throws InterruptedException {
        EncryptionParams params = EncryptionParams.newTestParams(new Random(1), CryptoConstants.CURVE,
                CryptoConstants.DIGEST);

        System.out.println("Warming up JIT");
        _runManyRunnablesBenchmark(params, 1, false);
        _runQueueBenchmark(params, 1, false);

        for (int threads : THREADS) {
            System.out.printf("\nRunning test with %d threads:\n", threads);
            _runManyRunnablesBenchmark(params, threads, true);
            _runQueueBenchmark(params, threads, true);
        }
    }

    private static void _runManyRunnablesBenchmark(EncryptionParams params, int threads, boolean doPrint)
            throws InterruptedException {
        ExecutorService executor = Executors.newFixedThreadPool(threads);
        Stopwatch watch = Stopwatch.createStarted();
        for (int i = 0; i < NUMBER_OF_MULTS; i++) {
            final BigInteger factor = params.getRandomIndex();
            executor.submit(() -> params.getGenerator().multiply(factor));
        }
        executor.shutdown();
        executor.awaitTermination(1000, TimeUnit.DAYS);
        watch.stop();

        if (doPrint) {
            System.out.printf("  Many runnables: %s\n", watch.toString());
        }
    }

    private static void _runQueueBenchmark(EncryptionParams params, int threads, boolean doPrint)
            throws InterruptedException {
        ExecutorService executor = Executors.newFixedThreadPool(threads);
        final BlockingQueue<BigInteger> factorQueue = new ArrayBlockingQueue<>(QUEUE_SIZE);
        for (int i = 0; i < threads; i++) {
            executor.submit(() -> {
                BigInteger factor = factorQueue.take();
                while (factor != QUEUE_EMPTY_FACTOR) {
                    params.getGenerator().multiply(factor);
                    factor = factorQueue.take();
                }
                return null;
            });
        }
        executor.shutdown();

        Stopwatch watch = Stopwatch.createStarted();
        for (int i = 0; i < NUMBER_OF_MULTS; i++) {
            factorQueue.put(params.getRandomIndex());
        }
        for (int i = 0; i < threads; i++) {
            factorQueue.put(QUEUE_EMPTY_FACTOR);
        }
        executor.awaitTermination(1000, TimeUnit.DAYS);
        watch.stop();

        if (doPrint) {
            System.out.printf("  Synchronized Queue: %s\n", watch.toString());
        }
    }
}
