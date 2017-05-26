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
import com.google.common.collect.ImmutableList;
import org.bouncycastle.math.ec.ECPoint;

import solidus.state.LocalBank;
import solidus.state.User;
import solidus.state.pvorm.EncryptedPvorm;
import solidus.trans.Transaction;
import solidus.trans.TransactionHeader;
import solidus.trans.TransactionRequest;
import solidus.util.CryptoConstants;
import solidus.util.DaemonThreadFactory;
import solidus.util.EncryptionParams;

import java.math.BigInteger;
import java.util.List;
import java.util.Random;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * This class implements a end2end transaction
 */
public class EndToEndTransactionsBenchmark {
    private static final int JIT_ITERS = 500;
    private static final int TESTS = 10;
    private static final int TEST_ITERS = 500;

    private static final int MAX_BALANCE = 1 << 10;

    private static final int TREE_DEPTH = 15;
    private static final int BUCKET_SIZE = 3;
    private static final int STASH_SIZE = 25;
    private static final int ORAM_ELTS = (1 << TREE_DEPTH);

    // private static final int ENCRYPTOR_THREADS = 1;
    // private static final int ENCRYPTOR_QUEUE_SIZE = 1000;
    private static final List<Integer> PROOF_THREADS = ImmutableList.of(1, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20);

    private static List<User> _createAccounts(int size, EncryptionParams params, ECPoint bankPublicKey) {
        ImmutableList.Builder<User> keysBuilder = new ImmutableList.Builder<>();
        for (int i = 0; i < size; i++) {
            BigInteger r = BigInteger.valueOf(i + 100L);
            keysBuilder.add(new User(params, bankPublicKey, r));
        }
        return keysBuilder.build();
    }

    public static void main(String argv[]) throws InterruptedException {
        EncryptionParams params = new EncryptionParams.Builder(new Random(1), CryptoConstants.CURVE,
                CryptoConstants.DIGEST).normalizePoints().useFastTestEncryptor()
                        // .setEncryptorThreads(ENCRYPTOR_THREADS)
                        // .setEncryptorQueueSize(ENCRYPTOR_QUEUE_SIZE)
                        .setMaxDiscreteLog(MAX_BALANCE).forTesting().build();

        BigInteger bankAPrivateEncKey = BigInteger.valueOf(3L);
        ECPoint bankAPublicEncKey = params.getGenerator().multiply(bankAPrivateEncKey).normalize();

        BigInteger bankBPrivateEncKey = BigInteger.valueOf(5L);
        ECPoint bankBPublicEncKey = params.getGenerator().multiply(bankBPrivateEncKey).normalize();

        System.out.println("# Creating " + ORAM_ELTS + " users");

        List<User> users1 = _createAccounts(ORAM_ELTS, params, bankAPublicEncKey);
        List<User> users2 = _createAccounts(ORAM_ELTS, params, bankBPublicEncKey);

        System.out.println("# Start building Oram with " + ORAM_ELTS + " leaves");

        Stopwatch buildBanks = Stopwatch.createStarted();
        LocalBank bankA = new LocalBank(params, TREE_DEPTH, BUCKET_SIZE, STASH_SIZE, bankAPrivateEncKey,
                BigInteger.valueOf(3L), users1);

        LocalBank bankB = new LocalBank(params, TREE_DEPTH, BUCKET_SIZE, STASH_SIZE, bankBPrivateEncKey,
                BigInteger.valueOf(5L), users1);

        // take a snapshot before updating. Not timing it because in this
        // doesn't happen in real blockchain
        EncryptedPvorm snapshotBankA = bankA.getEncryptedPvorm();
        EncryptedPvorm snapshotBankB = bankB.getEncryptedPvorm();

        buildBanks.stop();
        System.out.println("# Two banks built in " + buildBanks);

        // a random user
        User testUser1 = users1.get(0);
        User testUser2 = users2.get(1);

        System.out.println("# Now warming up JIT.");
        ExecutorService executor = Executors.newFixedThreadPool(8, new DaemonThreadFactory("ProofThread"));
        _runBenchmark(1, JIT_ITERS, false, testUser1, testUser2, bankA, bankB, snapshotBankA, snapshotBankB, executor,
                8);

        executor.shutdown();
        try {
            if (!executor.awaitTermination(10, TimeUnit.SECONDS)) {
                throw new RuntimeException("Executor shutdown timed out");
            }
        } catch (InterruptedException e) {
            System.err.println("Executor shutdown interrupted");
            throw e;
        }

        System.out.println("# JIT is warm (hopefully)");

        for (int threadCount : PROOF_THREADS) {
            System.out.println();
            System.out.printf("# Test with %d worker threads.\n", threadCount);
            executor = (threadCount == 0 ? null
                    : Executors.newFixedThreadPool(threadCount, new DaemonThreadFactory("ProofThread")));

            _runBenchmark(TEST_ITERS, TESTS, true, testUser1, testUser2, bankA, bankB, snapshotBankA, snapshotBankB,
                    executor, threadCount);

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

    private static void _runBenchmark(int iterations, int rounds, boolean doPrint, User testUser1, User testUser2,
            LocalBank bankA, LocalBank bankB, EncryptedPvorm snapshotBankA, EncryptedPvorm snapshotBankB,
            ExecutorService executor, int numThread) {

        long[] genTimes = new long[rounds];
        long[] verTimes = new long[rounds];
        long genTotal = 0;
        long verTotal = 0;

        for (int i = 0; i < rounds; i++) {
            Stopwatch genWatch = Stopwatch.createUnstarted();
            Stopwatch verWatch = Stopwatch.createUnstarted();
            // note that each iteration runs two (2) transactions
            for (int j = 0; j < iterations; j++) {
                genWatch.start();
                TransactionRequest transReq = testUser1.buildTransactionRequest(bankB.getPublicEncryptionKey(),
                        testUser2.getAccountKey(), 10L);
                TransactionHeader header = bankA.generateHeader(transReq, executor);
                Transaction.SenderInfo senderInfo = bankA.sendTransaction(header, executor);
                Transaction.ReceiverInfo receiverInfo = bankB.receiveTransaction(header, executor);
                genWatch.stop();

                verWatch.start();
                snapshotBankA.verifyUpdate(senderInfo.getUpdate(), executor);
                snapshotBankA.applyLastVerifiedUpdate();
                snapshotBankB.verifyUpdate(receiverInfo.getUpdate(), executor);
                snapshotBankB.applyLastVerifiedUpdate();
                senderInfo.verifySignature(header.getSourceBankKey());
                receiverInfo.verifySignature(header.getDestBankKey());
                verWatch.stop();

                genWatch.start();
                transReq = testUser2.buildTransactionRequest(bankA.getPublicEncryptionKey(), testUser1.getAccountKey(),
                        10L);
                header = bankB.generateHeader(transReq, executor);
                senderInfo = bankB.sendTransaction(header, executor);
                receiverInfo = bankA.receiveTransaction(header, executor);
                genWatch.stop();

                verWatch.start();
                snapshotBankA.verifyUpdate(receiverInfo.getUpdate(), executor);
                snapshotBankA.applyLastVerifiedUpdate();
                snapshotBankB.verifyUpdate(senderInfo.getUpdate(), executor);
                snapshotBankB.applyLastVerifiedUpdate();
                receiverInfo.verifySignature(header.getSourceBankKey());
                senderInfo.verifySignature(header.getDestBankKey());
                verWatch.stop();
            }
            genTimes[i] = genWatch.elapsed(TimeUnit.MILLISECONDS);
            genTotal += genTimes[i];
            verTimes[i] = verWatch.elapsed(TimeUnit.MILLISECONDS);
            verTotal += verTimes[i];
        }
        // note each iteration has two transactions
        double genAvg = (double) genTotal / (rounds * iterations * 2);
        double verAvg = (double) verTotal / (rounds * iterations * 2);
        double genStdErr = 0;
        double verStdErr = 0;
        for (int i = 0; i < rounds; i++) {
            genStdErr += Math.pow(((double) genTimes[i] / (iterations * 2)) - genAvg, 2);
            verStdErr += Math.pow(((double) verTimes[i] / (iterations * 2)) - verAvg, 2);
        }
        genStdErr = Math.sqrt(genStdErr / rounds);
        verStdErr = Math.sqrt(verStdErr / rounds);

        if (doPrint) {
            System.out.printf("#  generation:   avg %.2fms; stderr %.2f\n", genAvg, genStdErr);
            System.out.printf("#  verification: avg %.2fms; stderr %.2f\n", verAvg, verStdErr);
            System.out.printf("%d %.2f %.2f %.2f %.2f\n", numThread, genAvg, verAvg, genStdErr, verStdErr);
        }
    }
}
