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
import org.bouncycastle.math.ec.ECPoint;

import solidus.state.LocalBank;
import solidus.state.RemoteBank;
import solidus.state.User;
import solidus.trans.TransactionRequest;
import solidus.util.CryptoConstants;
import solidus.util.EncryptionParams;
import solidus.zookeeper.ZooKeeperDriver;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Logger;
import java.util.stream.Collectors;

public class SolidusOnZooKeeperCircular {
    private static final long TXN_TIMEOUT_DURATION = 1;
    private static final TimeUnit TXN_TIMEOUT_UNIT = TimeUnit.DAYS;

    private static final int MAX_BALANCE = 10;
    private static final int MAX_DISCRETE_LOG_BITS = 30;

    private static final int BUCKET_SIZE = 3;
    private static final int STASH_SIZE = 25;
    private static final int TREE_DEPTH = 15;

    private static final TimeUnit SHUTDOWN_TIMER_UNIT = TimeUnit.MINUTES;
    private static final long SHUTDOWN_TIMER_VALUE = 10;
    private static final int TEST_TXN_AMOUNT = 4800;

    private SolidusOnZooKeeperCircular() {}

    public static void main(String[] args) throws IOException, InterruptedException {
        System.out.println("Hello Fan.");
        if (args.length < 1) {
            System.out.println("Please supply cfg_file");
            System.exit(-1);
        }
        Path configFile = Paths.get(args[0]);
        List<String> configOptions = Files.readAllLines(configFile);
        if (configOptions.size() != 5) {
            System.out.println("Configuration file has the wrong number of entries.");
            return;
        }

        String connectionString = configOptions.get(0);
        BigInteger encryptionKey = new BigInteger(configOptions.get(1));
        BigInteger signingKey = new BigInteger(configOptions.get(2));
        int numberOfUsers = Integer.parseInt(configOptions.get(3));
        int numberOfNodes = Integer.parseInt(configOptions.get(4));

        EncryptionParams params = new EncryptionParams.Builder(new Random(), CryptoConstants.CURVE,
                CryptoConstants.DIGEST).normalizePoints().setCompressSerializedPoints(false)
                        .setTransactionTimeout(TXN_TIMEOUT_DURATION, TXN_TIMEOUT_UNIT)
                        // .setEncryptorThreads(ENCRYPTOR_THREADS)
                        .setMaxDiscreteLog(MAX_BALANCE).setMaxDiscreteLogBits(MAX_DISCRETE_LOG_BITS)
                        // .setLookupTableGap(LOOKUP_TABLE_GAP)
                        .useFastTestEncryptor().forTesting().build();

        System.out.println("Creating accounts...");
        ECPoint publicEncryptionKey = params.getGenerator().multiply(encryptionKey).normalize();
        List<User> users = _createAccounts(numberOfUsers, params, publicEncryptionKey);

        LocalBank bank = new LocalBank(params, TREE_DEPTH, BUCKET_SIZE, STASH_SIZE, encryptionKey, signingKey, users);
        System.out.println("This is " + _getIdFromKey(bank.getPublicEncryptionKey()));

        Logger logger = Logger.getLogger("benchmarks");
        try (ZooKeeperDriver driver = new ZooKeeperDriver(bank, params, 5, connectionString, false)) {
            new Thread(driver).start();

            Collection<RemoteBank> remoteBanks = driver.getRemoteBanks();

            // keep pinging peer banks until it sees (numberOfNodes - 1) all
            // peer banks are online
            System.out.println("Waiting for the other " + (numberOfNodes - 1) + " peers");
            while (remoteBanks.size() < numberOfNodes - 1) {
                Thread.sleep(1000);
            }

            // sort banks by ID to get a deterministic next hop
            String bankId = _getIdFromKey(bank.getPublicSigKey());
            List<String> bankIds = new ArrayList<>();
            bankIds.add(bankId);

            for (RemoteBank remoteBank : remoteBanks) {
                bankIds.add(_getIdFromKey(remoteBank.getEncryptionKey()));
            }
            Collections.sort(bankIds);

            String nextBankId = bankIds.get((bankIds.indexOf(bankId) + 1) % bankIds.size());
            logger.info("Next in the circle is " + nextBankId);

            driver.watchPath(Paths.get("/starttest"), () -> {
                try {
                    System.out.println("Start testing");
                    RemoteBank remoteBank = remoteBanks.stream()
                            .filter(b -> _getIdFromKey(b.getEncryptionKey()).equals(nextBankId))
                            .collect(Collectors.toList()).get(0);

                    _testBatchTransactions(driver, bank.getUsers().get(0), remoteBank.getEncryptionKey(),
                            remoteBank.getUserKeys().get(0), 0L, TEST_TXN_AMOUNT);
                } catch (ArrayIndexOutOfBoundsException e) {
                    logger.warning("Can't finish circle test: next hop disappeared");
                } catch (Exception e) {
                    e.printStackTrace();
                }
            });

            System.out.println("# Ready.");

            CountDownLatch exitLatch = new CountDownLatch(1);
            // block the main thread indefinitely
            exitLatch.await();
            driver.shutdown();
            driver.awaitTermination();
            System.out.println("# Bye.");
        }
    }

    private static List<User> _createAccounts(int size, EncryptionParams params, ECPoint bankPublicKey) {
        ImmutableList.Builder<User> keysBuilder = new ImmutableList.Builder<>();
        for (int i = 0; i < size; i++) {
            keysBuilder.add(new User(params, bankPublicKey, params.getRandomIndex()));
        }
        return keysBuilder.build();
    }

    private static String _getIdFromKey(ECPoint point) {
        return Base64.getUrlEncoder().encodeToString(point.getEncoded(true));
    }

    private static void _testBatchTransactions(ZooKeeperDriver driver, User user, ECPoint recvBankKey,
            ECPoint recvUserKey, long value, int nTxn) throws IOException, InterruptedException {
        Logger logger = Logger.getLogger("benchmarks");
        ImmutableList<TransactionRequest> requests;
        System.out.println("# Preparing transactions...");
        requests = _getTxnRequestBatch(user, recvBankKey, recvUserKey, value, nTxn);

        System.out.println("# Starting sending transactions...");
        driver.clearGlobalTransactionCallbacks();

        final AtomicInteger totalClearedTxnCount = new AtomicInteger(0);
        final Stopwatch watch = Stopwatch.createUnstarted();

        driver.registerGlobalTransactionCallback((txId) -> {
            totalClearedTxnCount.incrementAndGet();
        });

        Timer shutdownTimer = new Timer();
        shutdownTimer.schedule(new TimerTask() {
            @Override
            public void run() {
                watch.stop();
                _printResults(totalClearedTxnCount.get(), watch.elapsed(TimeUnit.SECONDS));
                try {
                    System.out.println("# Exiting after 5s...");
                    Thread.sleep(5000);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                    System.exit(-1);
                }
                System.exit(0);
            }
        }, SHUTDOWN_TIMER_UNIT.toMillis(SHUTDOWN_TIMER_VALUE));

        watch.start();
        for (TransactionRequest req : requests) {
            logger.fine(String.format("sending transaction %s to %s", req.getID().toString(),
                    _getIdFromKey(req.getDestBankKey())));
            boolean ret = driver.requestTransaction(req);
            if (!ret) {
                throw new IOException("can't send transactions to zookeeper");
            }
        }
    }

    private static ImmutableList<TransactionRequest> _getTxnRequestBatch(User sourceUser, ECPoint recvBankKey,
            ECPoint recvUserKey, long value, int nTxn) {
        ImmutableList.Builder<TransactionRequest> requestBuilder = ImmutableList.builder();
        for (int i = 0; i < nTxn; i++) {
            requestBuilder.add(sourceUser.buildTransactionRequest(recvBankKey, recvUserKey, value));
        }
        return requestBuilder.build();
    }

    private static void _printResults(int numberOfRequests, long elapsedTime) {
        System.out.printf("# %d transactions processed in %d s. \n", numberOfRequests, elapsedTime);
        System.out.printf("# Throughput: %.2f [tx/sec] \n", 1.0 * numberOfRequests / elapsedTime);
        System.out.printf("%.4f\n", 1.0 * numberOfRequests / elapsedTime);
    }
}
