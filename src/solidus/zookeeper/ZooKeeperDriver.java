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

package solidus.zookeeper;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.SortedMap;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import java.util.function.Predicate;
import java.util.logging.Logger;
import java.util.stream.Collectors;

import com.google.common.collect.ImmutableSortedMap;

import org.apache.zookeeper.CreateMode;
import org.apache.zookeeper.KeeperException;
import org.apache.zookeeper.WatchedEvent;
import org.apache.zookeeper.Watcher;
import org.apache.zookeeper.ZooDefs;
import org.apache.zookeeper.ZooKeeper;
import org.bouncycastle.math.ec.ECPoint;

import solidus.io.SerialHelpers;
import solidus.io.TopLevelSerializers;
import solidus.state.LocalBank;
import solidus.state.RemoteBank;
import solidus.state.User;
import solidus.state.pvorm.PvormUpdate;
import solidus.trans.Transaction;
import solidus.trans.TransactionHeader;
import solidus.trans.TransactionRequest;
import solidus.util.DaemonThreadFactory;
import solidus.util.EncryptionParams;

/**
 * This class provides a driver to interface Solidus with ZooKeeper. Each
 * {@code ZooKeeperDriver} instance connects a single bank to the ZooKeeper
 * system. The bank must be constructed (as a {@link solidus.state.LocalBank}
 * object) with all of its user accounts already created (as
 * {@link solidus.state.User} objects) prior to construction of the
 * {@code ZooKeeperDriver}.
 *
 * Once the driver exists, all future interaction with the Bank should be
 * mediated through the {@code ZooKeeperDriver} object. It can service requests
 * for transactions and callbacks when transactions are completed.
 *
 * All inter-bank communication is handled by writing to files with a
 * pre-determined structure to ZooKeeper. Files that do not need to persist are
 * cleaned up when no longer needed.
 *
 * TODO: This impelentation currently does not handle timeouts, malformed input,
 * invalid proofs, or intra-bank transactions.
 *
 * @author jyamy42@gmail.com and ethan@cs.cornell.edu
 */
public class ZooKeeperDriver implements Runnable, AutoCloseable {
    /**
     * This provides an interface by which clients can request callbacks when
     * transactions requests either clear or fail for some reason. The success
     * callback is designed to be invoked when a transaction clears and settles
     * properly, while the failure callback is designed to be invoked when an
     * error occurs related to a transaction.
     *
     * @author ethan@cs.cornell.edu
     */
    public interface RequestCallback {
        /**
         * The method to invoke when a transaction successfuly clears and
         * settles.
         */
        public void callSuccess();

        /**
         * The the method to invoke when an error occrs.
         *
         * @param e the error that caused the failure.
         */
        public void callFailure(Exception e);
    }

    private final InternalDriver m_driver;

    /**
     * Constructs a new driver for a bank with a given set of parameters and
     * connects to the specified ZooKeeper instance. This driver will connect to
     * the system, broadcast the entrance of a new bank, bootstrap known
     * information about other banks, and being processing transactions.
     *
     * @param bank The bank used by this Solidus node. This bank should not be
     *            used for any other {@code ZooKeeperDriver} instances.
     * @param params The system parameters currently in use.
     * @param threads The number of threads to use for creating and verifying
     *            transactions. Creation and verification are both highly
     *            parallelizable and this determines the size of the thread pool
     *            used for these actions (the same thread pool is used for
     *            both).
     * @param connectString The string to pass to a <a target="_blank" href=
     *            "https://zookeeper.apache.org/doc/r3.4.9/api/index.html?org/apache/zookeeper/ZooKeeper.html">
     *            ApacheZooKeeper object</a> to connect to the ZooKeeper
     *            service.
     * @throws IOException If an error occurs connecting to the ZooKeeper
     *             system.
     */
    public ZooKeeperDriver(LocalBank bank, EncryptionParams params, int threads, String connectString)
            throws IOException {
        this(bank, params, threads, connectString, true);
    }

    /**
     * Constructs a new driver for a bank with a given set of parameters and
     * connects to the specified ZooKeeper instance while allowing the system to
     * turn off transaction verification. This driver will connect to the
     * system, broadcast the entrance of a new bank, bootstrap known information
     * about other banks, and being processing transactions.
     *
     * This constructor allows the system to turn off online verification of
     * third-party transactions. If transactions are not verified online, many
     * of the Solidus security guarantees are not maintained, but performance
     * improves significantly (especially if there are many banks in the sysem)
     * and errors can be identified and attributed offline.
     *
     * @param bank The bank used by this Solidus node. This bank should not be
     *            used for any other {@code ZooKeeperDriver} instances.
     * @param params The system parameters currently in use.
     * @param threads The number of threads to use for creating and verifying
     *            transactions. Creation and verification are both highly
     *            parallelizable and this determines the size of the thread pool
     *            used for these actions (the same thread pool is used for
     *            both).
     * @param connectString The string to pass to a <a target="_blank" href=
     *            "https://zookeeper.apache.org/doc/r3.4.9/api/index.html?org/apache/zookeeper/ZooKeeper.html">
     *            ApacheZooKeeper object</a> to connect to the ZooKeeper
     *            service.
     * @param runVerification Specifies whether or not to run verification on
     *            third-party transactions.
     * @throws IOException If an error occurs connecting to the ZooKeeper
     *             system.
     */
    public ZooKeeperDriver(LocalBank bank, EncryptionParams params, int threads, String connectString,
            boolean runVerification) throws IOException {
        m_driver = new InternalDriver(bank, params, threads, connectString, runVerification);
    }

    /**
     * Produces the currently known set of other banks in the system. The
     * collection returned is an immutable view into the driver's knowledge of
     * other banks, so it will change if new banks enter the system.
     *
     * @return The currently known set of other banks in the system.
     */
    public Collection<RemoteBank> getRemoteBanks() {
        return Collections.unmodifiableCollection(m_driver.m_otherBanks.values());
    }

    /**
     * Checks if this bank is currently running.
     *
     * @return {@code false} if this driver has terminated, false otherwise.
     * @see #shutdown
     * @see #awaitTermination
     * @see #awaitTermination(long, TimeUnit)
     */
    public boolean isRunning() {
        return m_driver.m_runningLatch.getCount() > 0;
    }

    /**
     * Marks this driver as no longer accepting new requests and tells it to
     * terminate once all currently pending requests have been processed.
     *
     * @throws InterruptedException If this thread is interrupted while queuing
     *             the "terminate" instruction.
     * @see #isRunning
     * @see #awaitTermination
     * @see #awaitTermination(long, TimeUnit)
     */
    public void shutdown() throws InterruptedException {
        synchronized (m_driver.m_pendingRequests) {
            m_driver.m_isShutdown = true;
            m_driver.m_pendingRequests.put(TransactionRequest.TERMINATION_REQUEST);
        }
    }

    /**
     * Blocks until this driver has terminated.
     *
     * @throws InterruptedException If the thread is interrupted before the
     *             driver terminates.
     * @see #isRunning
     * @see #shutdown
     * @see #awaitTermination(long, TimeUnit)
     */
    public void awaitTermination() throws InterruptedException {
        m_driver.m_runningLatch.await();
    }

    /**
     * Blocks until this driver has terminated or the specified time has
     * elapsed.
     *
     * @param duration the amount of time to wait
     * @param unit the time unit in which to interpret {@code duration}
     * @return {@code true} if the driver terminated, {@code false} if the wait
     *         timed out.
     * @throws InterruptedException if the thread is interrupted before the
     *             driver terminates or the wait times out.
     * @see #isRunning
     * @see #shutdown
     * @see #awaitTermination
     */
    public boolean awaitTermination(long duration, TimeUnit unit) throws InterruptedException {
        return m_driver.m_runningLatch.await(duration, unit);
    }

    /**
     * Requests a new transaction be executed by the bank owned by this driver
     * instance. The transaction will be executed at the next available
     * opportunity. Requested transactions originating from this bank are
     * executed in FIFO order, but may be preempted by incoming transactions
     * from other banks. This means there is, in theory, an arbitrary delay
     * before the transaction is processed.
     *
     * Transactions are processed asynchornously and this method provides no
     * indication of when the transaction is actually processed.
     *
     * This driver has a limited size buffer of pending outgoing transactions.
     * If the buffer is full, this request will be rejected.
     *
     * @param request The transaction request to process.
     * @return {@code true} if the request was successfully added to this
     *         driver's buffer, {@code false} if the buffer was full.
     * @throws IllegalArgumentException If the request's signature is invalid.
     * @throws IllegalStateException If this driver has been shut down.
     *
     * @see #requestTransaction(TransactionRequest, RequestCallback)
     */
    public boolean requestTransaction(TransactionRequest request) {
        return requestTransaction(request, null);
    }

    /**
     * Requests a new transaction be executed by the bank owned by this driver
     * instance with a callback to execute on completion. The transaction will
     * be executed at the next available opportunity. Requested transactions
     * originating from this bank are executed in FIFO order, but may be
     * preempted by incoming transactions from other banks. This means there is,
     * in theory, an arbitrary delay before the transaction is processed. When
     * the transaction is processed, if it successfully settles, the success
     * case of {@code callback} will be invoked. If an error occurs processing
     * the transaction, the failure case of {@code callback} will be invoked.
     *
     * Transactions are processed asynchronously and callbacks may be executed
     * in a different thread.
     *
     * This driver has a limited size buffer of pending outgoing transactions.
     * If the buffer is full, this request will be rejected.
     *
     * @param request The transaction request to process.
     * @param callback The success and failure callbacks to invoke with this
     *            request is processed.
     * @return {@code true} if the request was successfully added to this
     *         driver's buffer, {@code false} if the buffer was full.
     * @throws IllegalArgumentException If the request's signature is invalid.
     * @throws IllegalStateException If this driver has been shut down.
     *
     * @see #requestTransaction(TransactionRequest)
     */
    public boolean requestTransaction(TransactionRequest request, RequestCallback callback) {
        if (!request.verifySignature()) throw new IllegalArgumentException("Request did not contain a valid signature");
        // TODO: Ensure that the transaction ID is valid and unique!

        synchronized (m_driver.m_pendingRequests) {
            if (m_driver.m_isShutdown) throw new IllegalStateException("Cannot request transaction after shutdown");

            if (m_driver.m_pendingRequests.offer(request)) {
                m_driver.m_logger.fine("Request " + request.getID() + " accepted");
                if (callback != null) m_driver.m_requestCallbacks.put(request.getID(), callback);
                return true;
            }
            return false;
        }
    }

    /**
     * Registers a callback to execute whenever any transaction is cleared,
     * regardless of the banks involved.
     *
     * @param callback the operation to call with the transaction ID when any
     *            transaction clears.
     */
    public void registerGlobalTransactionCallback(Consumer<Transaction.ID> callback) {
        m_driver.m_globalTransactionCallbacks.add(callback);
    }

    /**
     * Removes all global transaction callbacks from this object. Currently
     * registered callbacks will no longer be called for future transactions.
     */
    public void clearGlobalTransactionCallbacks() {
        m_driver.m_globalTransactionCallbacks.clear();
    }

    /**
     * NOTE! This is for testing only! Watches a file path that is otherwise not
     * in use.
     *
     * @param path The filepath to watch. This cannot be a path used internally.
     * @param callback the callback to execute when anything happens to the
     *            given filepath.
     */
    public void watchPath(Path path, Runnable callback) {
        m_driver.watchPath(path, callback);
    }

    /**
     * Connects this driver to the ZooKeeper instance specified in the
     * constructor, bootstraps it into the system, and starts it running. A
     * running driver is capable of accepting transaction requests and
     * processing both incoming and outgoing transactions.
     *
     * Bootstrapping entails posting this Bank's initial public state to the
     * ledger and reading in the initial states of all other banks as well as
     * all settled transactions (and updating other banks appropriately). This
     * operation can take some time if there are many other banks or their
     * states are large.
     *
     * @throws IllegalStateException If this driver is already running.
     */
    @Override
    public void run() {
        m_driver.run();
    }

    /**
     * Shuts down the driver if it is not already shut down, waits for all
     * pending outgoing requests to be processed, and then exits the network.
     *
     * @throws InterruptedException If this thread is interrupted while waiting
     *             for all pending outgoing transaction requests to be
     *             processed.
     */
    @Override
    public void close() throws InterruptedException {
        shutdown();
        awaitTermination();
        m_driver.m_zk.close();
    }

    /**
     * This nested class contains all of the actual logic to interface Solidus
     * with ZooKeeper. It is separated out into a nested class in order to
     * remove visibility of the internal methods that must be public to
     * implement {@code org.apache.zookeeper.Watcher}.
     */
    private static class InternalDriver implements Runnable, Watcher {
        /**
         * The list of common directories that all Solidus nodes on this
         * ZooKeeper instance will use.
         */
        private enum CommonDir {
            INIT_STATE("/initial-state"), LOCK("/lock/"), HEADER("/header/"), SENDER_INFO("/sender-info/"), COMMIT(
                    "/commit/");

            private final Path m_path;

            private CommonDir(String pathStr) {
                m_path = Paths.get(pathStr);
            }

            public Path getPath() {
                return m_path;
            }

            public Path resolve(String filename) {
                return m_path.resolve(filename);
            }

            public String resolveToString(String filename) {
                return resolve(filename).toString();
            }

            @Override
            public String toString() {
                return m_path.toString();
            }
        }

        // ZooKeeper supports 1 MiB, but we use 512 KiB
        private static final int MAX_FILE_SIZE_BYTES = 1 << 19;

        private static final int REQUEST_QUEUE_SIZE = 5000;
        private static final int SESSION_TIMEOUT = 12000; // in ms

        private static final String COMMIT_FILENAME = "txn";

        private final Logger m_logger;

        private final EncryptionParams m_params;
        private final LocalBank m_bank;
        private final Map<String, RemoteBank> m_otherBanks;

        private final boolean m_runVerification;

        private final String m_bankId;
        private final String m_bankLockPath;

        private final ExecutorService m_executor;

        private final Collection<Consumer<Transaction.ID>> m_globalTransactionCallbacks;

        private final BlockingQueue<TransactionRequest> m_pendingRequests;
        private final Map<Transaction.ID, RequestCallback> m_requestCallbacks;
        private final Set<Transaction.ID> m_outgoingTxIds;

        private final ZooKeeper m_zk;

        private final AtomicBoolean m_isStarted;
        private final CountDownLatch m_runningLatch;
        private boolean m_isShutdown;

        private volatile Transaction.ID m_currentTxId;
        private volatile TransactionHeader m_currentTxHeader;
        private volatile RemoteBank m_currentOtherBank;
        private volatile Transaction.ReceiverInfo m_currentReceiverInfo;

        private final Object m_processCommitLock = new Object();
        private int m_maxTxNumProcessed;

        public InternalDriver(LocalBank bank, EncryptionParams params, int threads, String connectString,
                boolean runVerification) throws IOException {
            m_logger = Logger.getLogger("solidus");

            m_params = params;
            m_bank = bank;
            m_otherBanks = new ConcurrentHashMap<>();

            m_runVerification = runVerification;

            m_bankId = _getIdFromKey(m_bank.getPublicEncryptionKey());
            m_bankLockPath = CommonDir.LOCK.resolveToString(m_bankId);

            if (threads > 0) {
                m_executor = Executors.newFixedThreadPool(threads, new DaemonThreadFactory("ProofWorker"));
            } else {
                m_executor = null;
            }

            m_globalTransactionCallbacks = new ArrayList<>();

            m_pendingRequests = new ArrayBlockingQueue<>(REQUEST_QUEUE_SIZE);
            m_requestCallbacks = new ConcurrentHashMap<>();
            m_outgoingTxIds = ConcurrentHashMap.newKeySet();

            m_zk = new ZooKeeper(connectString, SESSION_TIMEOUT, this);

            m_isStarted = new AtomicBoolean(false);
            m_runningLatch = new CountDownLatch(1);
            m_isShutdown = false;

            m_currentTxId = null;
            m_currentTxHeader = null;
            m_currentOtherBank = null;
            m_currentReceiverInfo = null;

            m_maxTxNumProcessed = -1;
        }

        /**
         * NOTE! This is for testing only! Watches a file path that is otherwise
         * not in use.
         *
         * @param path The filepath to watch. This cannot be a path used
         *            internally.
         * @param callback the callback to execute when anything happens to the
         *            given filepath.
         */
        public void watchPath(Path path, Runnable callback) {
            try {
                for (CommonDir dir : CommonDir.values()) {
                    if (path.startsWith(dir.getPath())) throw new IllegalArgumentException(
                            "Path [" + path + "] is used by the system and cannot be watched.");
                }

                m_zk.exists(path.toString(), (x) -> callback.run());
            } catch (KeeperException | InterruptedException e) {
                throw new RuntimeException("Something failed trying to watch path", e);
            }
        }

        private String _getIdFromKey(ECPoint point) {
            return Base64.getUrlEncoder().encodeToString(point.getEncoded(true));
        }

        private void _createFile(Path filepath, byte[] data) throws KeeperException, InterruptedException {
            m_zk.create(filepath.toString(), data, ZooDefs.Ids.OPEN_ACL_UNSAFE, CreateMode.PERSISTENT);
        }

        private byte[] _getData(Path directory, Transaction.ID txId) throws KeeperException, InterruptedException {
            return m_zk.getData(directory.resolve(txId.toString()).toString(), null, null);
        }

        private void _deleteFile(Path filepath) throws KeeperException, InterruptedException {
            try {
                m_zk.delete(filepath.toString(), -1);
            } catch (KeeperException e) {
                // We don't care about NoNode exceptions since we're just tyring
                // to
                // delete the file if it's there.
                if (e.code() != KeeperException.Code.NONODE) throw e;
            }
        }

        private void _handleOperationalException(Exception e) {
            if (m_currentTxId != null) {
                RequestCallback callback = m_requestCallbacks.get(m_currentTxId);
                // If a callback throws an exception, we just want to ignore it.
                // It's
                // the client's problem.
                try {
                    if (callback != null) callback.callFailure(e);
                } catch (Exception e2) {}
            }
            try {
                _releaseLock();
            } catch (KeeperException | InterruptedException e2) {
                // Really not much to be done here.
                e2.printStackTrace();
            }
        }

        @Override
        public void run() {
            if (!m_isStarted.compareAndSet(false, true))
                throw new IllegalStateException("Cannot start while already running.");

            try {
                _createCommonDirs();
                _readOtherBankStates();
                _processExistingCommits();
                _postInitialState();

                // Before we start, put a watch on the lock file.
                _watchLock();

                m_logger.fine("setup complete, now moving to txn processing");
                while (true) {
                    m_logger.fine("Waiting for incoming transaction");

                    TransactionRequest request = m_pendingRequests.take();
                    if (request == TransactionRequest.TERMINATION_REQUEST) break;

                    String otherBankId = _getIdFromKey(request.getDestBankKey());
                    if (!m_otherBanks.containsKey(otherBankId)) {
                        m_logger.warning(
                                "Trying to send to unknown bank " + otherBankId + ". Ignoring transaction request.");
                        continue;
                    }

                    Transaction.ID txId = request.getID();
                    m_outgoingTxIds.add(txId);

                    m_logger.fine("Processing request " + txId);

                    _lockBank(otherBankId, txId);

                    m_currentTxId = txId;
                    m_currentOtherBank = m_otherBanks.get(otherBankId);

                    _processExistingCommits();

                    m_logger.fine("Bank locks acquired");

                    m_currentTxHeader = m_bank.generateHeader(request, m_executor);

                    byte[] serialHeader = TopLevelSerializers.serializeTransactionHeader(m_params, m_currentTxHeader);
                    _createFile(CommonDir.HEADER.resolve(txId.toString()), serialHeader);

                    m_logger.fine("Posted header for txn " + txId);

                    byte[] senderInfo = TopLevelSerializers.serializeTxSenderInfo(m_params,
                            m_bank.sendTransaction(m_currentTxHeader, m_executor));
                    _createFile(CommonDir.SENDER_INFO.resolve(txId.toString()), senderInfo);

                    m_logger.fine("Posted proof for txn " + txId);
                }
            } catch (InterruptedException | KeeperException e) {
                _handleOperationalException(e);
            } finally {
                m_runningLatch.countDown();
            }
        }

        private void _createCommonDirs() throws InterruptedException, KeeperException {
            byte[] emptyArray = new byte[0];
            for (CommonDir dir : CommonDir.values()) {
                try {
                    _createFile(dir.getPath(), emptyArray);
                } catch (KeeperException e) {
                    // Ignore NodeExists exceptions. That just means the
                    // directories already exist (which means we're not the
                    // first
                    // bank into the system, which is fine).
                    if (e.code() != KeeperException.Code.NODEEXISTS) throw e;
                }
            }
        }

        private void _readOtherBankStates() throws InterruptedException, KeeperException {
            // Get the children and set a watch for future banks entering the
            // system.
            for (String bankId : m_zk.getChildren(CommonDir.INIT_STATE.toString(), this)) {
                if (!bankId.equals(m_bankId)) {
                    m_otherBanks.computeIfAbsent(bankId, this::_decodeBank);
                }
            }
        }

        private RemoteBank _decodeBank(String bankId) {
            m_logger.info("Bootstrapping new bank " + bankId);
            try {
                Path bankDir = CommonDir.INIT_STATE.resolve(bankId);
                byte[] encodedBootstrapParams = m_zk.getData(bankDir.toString(), null, null);
                InputStream inStream = new ByteArrayInputStream(encodedBootstrapParams);
                if (!SerialHelpers.verifyHeaders(inStream, m_params)) {
                    m_logger.info(
                            () -> String.format("Bank %s cannot be included due to invalid parameters.\n", bankId));
                    return null;
                }

                int numFiles = SerialHelpers.readInt(inStream);
                ByteArrayOutputStream byteOutStream = new ByteArrayOutputStream();
                for (int i = 0; i < numFiles; i++) {
                    String nextFileName = bankDir.resolve(Integer.toString(i)).toString();
                    // It's possible we got the name before all of the data was
                    // written. If a file is missing, wait for it to show up.
                    //
                    // TODO: The writer could have crashed or had a bug, this
                    // should time out eventually.
                    boolean loadedData = false;
                    while (!loadedData) {
                        try {
                            byteOutStream.write(m_zk.getData(nextFileName, null, null));
                            loadedData = true;
                        } catch (KeeperException e) {
                            if (e.code() != KeeperException.Code.NONODE) throw e;

                            final CountDownLatch remoteBootstrapLatch = new CountDownLatch(1);
                            while (m_zk.exists(nextFileName, (x) -> remoteBootstrapLatch.countDown()) == null) {
                                m_logger.fine("blocking waiting for file " + nextFileName + " to exist");
                                // For some reason the latch doesn't always
                                // fire,
                                // but we can just time out and try again.
                                remoteBootstrapLatch.await(10, TimeUnit.MILLISECONDS);
                            }
                        }
                    }
                }
                RemoteBank bank = RemoteBank.serialReadIn(new ByteArrayInputStream(byteOutStream.toByteArray()),
                        m_params);
                m_logger.fine("Bank " + bankId + " bootstrapped from " + numFiles + " files.");
                return bank;
            } catch (KeeperException e) {
                // This means there was a server error, but it might be
                // recoverable
                // if we just try again, so print failure and move on.
                e.printStackTrace();
                return null;
            } catch (InterruptedException | IOException e) {
                // These are problems locally and are not recoverable, but we
                // use
                // this in a Function, so we cannot throw checked exceptions.
                throw new RuntimeException(e);
            }
        }

        private void _postInitialState() throws InterruptedException, KeeperException {
            m_logger.info("Posting initial bank state to ledger");
            try {
                byte[] encodedRemoteBank = new RemoteBank(m_bank.getPublicEncryptionKey(), m_bank.getPublicSigKey(),
                        m_bank.getUsers().stream().map(User::getAccountKey).collect(Collectors.toList()),
                        m_bank.getEncryptedPvorm()).toByteArray(true);
                int numFiles = (encodedRemoteBank.length + MAX_FILE_SIZE_BYTES - 1) / MAX_FILE_SIZE_BYTES;
                m_logger.finer("Posting " + numFiles + " files");

                ByteArrayOutputStream headerOutStream = new ByteArrayOutputStream();
                SerialHelpers.writeHeaders(headerOutStream, m_params);
                SerialHelpers.writeInt(headerOutStream, numFiles);

                Path directory = CommonDir.INIT_STATE.resolve(m_bankId);
                _createFile(directory, headerOutStream.toByteArray());

                for (int i = 0; i < numFiles; i++) {
                    m_logger.finer("Posting initial state file " + i);
                    int start = i * MAX_FILE_SIZE_BYTES;
                    int end = Math.min(start + MAX_FILE_SIZE_BYTES, encodedRemoteBank.length);
                    byte[] data = Arrays.copyOfRange(encodedRemoteBank, start, end);
                    _createFile(directory.resolve(Integer.toString(i)), data);
                }
            } catch (IOException e) {
                // The only actual IO goes through ZooKeeper and will throw
                // KeeperExceptions, so we should never get here.
                throw new RuntimeException(e);
            }
            m_logger.fine("Done posting state to ledger");
        }

        @Override
        public void process(WatchedEvent event) {
            try {
                if (event.getType() == Watcher.Event.EventType.None) {
                    switch (event.getState()) {
                        case SyncConnected:
                            // Nothing to do here.
                            break;
                        case Disconnected:
                        case Expired:
                            // TODO: Stop accepting request.
                            break;
                        default:
                            m_logger.warning("Unexpected state from watched event: " + event.getState());
                            break;
                    }
                } else if (event.getType() == Watcher.Event.EventType.NodeCreated) {
                    Path fullPath = Paths.get(event.getPath());
                    String filename = fullPath.getFileName().toString();
                    Path parent = fullPath.getParent();
                    if (CommonDir.LOCK.getPath().equals(parent)) {
                        if (!m_bankId.equals(filename))
                            throw new IllegalStateException("We were somehow watching someone else's lock");

                        _processLock();
                    } else if (m_currentTxId == null || !m_currentTxId.toString().equals(filename)) {
                        throw new IllegalStateException(
                                "Received a notification for a file unrelated to the current transaction.");
                    } else if (CommonDir.HEADER.getPath().equals(parent)) {
                        _processIncomingHeader();
                    } else if (CommonDir.SENDER_INFO.getPath().equals(parent)) {
                        _processSenderInfo();
                    } else {
                        m_logger.severe("Watch triggered for creation of unexpected filepath: " + event.getPath());
                    }
                } else if (event.getType() == Watcher.Event.EventType.NodeChildrenChanged) {
                    if (event.getPath().equals(CommonDir.INIT_STATE.toString())) {
                        _readOtherBankStates();
                    } else if (event.getPath().equals(CommonDir.COMMIT.toString())) {
                        _processExistingCommits();
                    } else {
                        m_logger.severe("Watch triggered for child change of unexpected filepath: " + event.getPath());
                    }
                }
            } catch (KeeperException | InterruptedException e) {
                _handleOperationalException(e);
            } catch (RuntimeException e) {
                e.printStackTrace();
            }
        }

        private void _lockBank(String otherBankId, Transaction.ID txId) throws InterruptedException, KeeperException {
            // I have no idea why, but for some reason a transaction trying to
            // create two lock files at the same time seems to time out.
            // Instead, we grab the locks one at a time and use lexographic
            // ordering on ID strings to prevent deadlock.
            if (m_bankId.compareTo(otherBankId) < 0) {
                _lockOneBank(m_bankId, txId);
                _lockOneBank(otherBankId, txId);
            } else {
                _lockOneBank(otherBankId, txId);
                _lockOneBank(m_bankId, txId);
            }
        }

        private void _lockOneBank(String bankId, Transaction.ID txId) throws InterruptedException, KeeperException {
            m_logger.fine("Locking bank " + bankId + " for transaction " + txId);

            Path lockDir = CommonDir.LOCK.resolve(bankId);
            byte[] encodedTxId = txId.toByteArray();

            boolean lockAcquired = false;
            while (!lockAcquired) {
                try {
                    _createFile(lockDir, encodedTxId);
                    lockAcquired = true;
                } catch (KeeperException e) {
                    if (e.code() != KeeperException.Code.NODEEXISTS) throw e;

                    final CountDownLatch latch = new CountDownLatch(1);
                    if (m_zk.exists(lockDir.toString(), (x) -> latch.countDown()) != null) {
                        // For some reason the latch doesn't always fire,
                        // but we can just time out and try again.
                        latch.await(250, TimeUnit.MILLISECONDS);
                    }
                }
            }
            m_logger.fine("Acquired lock on bank " + bankId + " for transaction " + txId);
        }

        private void _watchLock() throws InterruptedException, KeeperException {
            m_logger.finer("in _watchLock()");
            if (m_currentTxId != null)
                throw new IllegalStateException("Cannot start watching a lock while processing a transaction");
            m_logger.finer("checking for watch lock");

            if (m_zk.exists(m_bankLockPath, this) != null) {
                m_logger.fine("Lock existed at watch point. Processing now");
                _processLock();
            }
        }

        private void _processLock() throws InterruptedException, KeeperException {
            // TODO: Make locks ephemeral and properly handle disconnects.

            // If the file already exists, someone else has grabbed the lock
            // already and we need to start processing the transaction.
            byte[] encodedTxId = m_zk.getData(m_bankLockPath, null, null);
            Transaction.ID newId = Transaction.ID.fromBytes(encodedTxId);
            if (!m_outgoingTxIds.remove(newId)) {
                m_logger.fine("Processing new incoming transaction: " + newId);

                m_currentTxId = newId;
                _watchForHeader();
            }
        }

        private void _watchForHeader() throws InterruptedException, KeeperException {
            if (m_currentTxId == null)
                throw new IllegalStateException("Cannot start watching a lock while processing a transaction");

            String headerPath = CommonDir.HEADER.resolveToString(m_currentTxId.toString());
            if (m_zk.exists(headerPath, this) != null) {
                _processIncomingHeader();
            }
        }

        private void _processIncomingHeader() throws InterruptedException, KeeperException {
            if (m_currentTxId == null)
                throw new IllegalStateException("Cannot handle header without active transaction id");
            m_logger.fine("Processing incoming header for txId " + m_currentTxId);

            String headerPath = CommonDir.HEADER.resolveToString(m_currentTxId.toString());
            byte[] encodedHeader = m_zk.getData(headerPath, null, null);
            m_currentTxHeader = TopLevelSerializers.deserializeTransactionHeader(m_params, encodedHeader);

            if (!m_currentTxHeader.getDestBankKey().equals(m_bank.getPublicEncryptionKey())) {
                m_logger.warning(String.format("Not processing transaction %s because it was for a bank %s not me (%s)",
                        m_currentTxId, _getIdFromKey(m_currentTxHeader.getDestBankKey()), m_bankId));
                return;
            }
            if (!m_currentTxHeader.verifyProofs()) {
                m_logger.warning("Not processing transaction because proofs did not verify.");
                return;
            }
            m_currentOtherBank = m_otherBanks.get(_getIdFromKey(m_currentTxHeader.getSourceBankKey()));

            // TODO: Maybe check that we're not already handling this?

            m_currentReceiverInfo = m_bank.receiveTransaction(m_currentTxHeader, m_executor);
            String sendInfoPath = CommonDir.SENDER_INFO.resolveToString(m_currentTxId.toString());
            m_logger.finer("Watching path " + sendInfoPath + " before committing transaction");

            if (m_zk.exists(sendInfoPath, this) != null) {
                m_logger.finer("Sender info already available, processing now");
                _processSenderInfo();
            }
        }

        private void _processSenderInfo() throws KeeperException, InterruptedException {
            if (m_currentTxId == null)
                throw new IllegalStateException("Cannot handle sender info without active transaction id");
            if (m_currentReceiverInfo == null)
                throw new IllegalStateException("Cannot handler sender info without receiver info ready");
            m_logger.fine("Processing incoming receiver signature for txId " + m_currentTxId);

            byte[] encodedSenderInfo = _getData(CommonDir.SENDER_INFO.getPath(), m_currentTxId);
            Transaction.SenderInfo senderInfo = TopLevelSerializers.deserializeTxSenderInfo(m_params,
                    encodedSenderInfo);

            // Make sure that this sender info is actually signed by the right
            // bank.
            if (!senderInfo.verifySignature(m_currentOtherBank.getSigVerKey())) {
                m_logger.warning("Signature for sender info did not verify.");
                return;
            }

            byte[] encodedTransaction = TopLevelSerializers.serializeTransaction(m_params,
                    new Transaction(senderInfo, m_currentReceiverInfo));
            m_zk.create(CommonDir.COMMIT.resolveToString(COMMIT_FILENAME), encodedTransaction,
                    ZooDefs.Ids.OPEN_ACL_UNSAFE, CreateMode.PERSISTENT_SEQUENTIAL);
        }

        private void _releaseLock() throws KeeperException, InterruptedException {
            m_logger.fine("Releasing lock and readying for new transaction");

            m_currentTxId = null;
            m_currentTxHeader = null;
            m_currentOtherBank = null;
            m_currentReceiverInfo = null;

            _deleteFile(CommonDir.LOCK.resolve(m_bankId));

            m_logger.finer("Lock released.");

            _watchLock();
        }

        private void _processExistingCommits() throws KeeperException, InterruptedException {
            m_logger.info("Processing existing commits.");

            // If another transaction is committed while we're processing, we
            // need
            // to delay a second round to make sure everything gets processed in
            // order, so just synchronize on something nobody else uses.
            synchronized (m_processCommitLock) {
                SortedMap<Integer, String> unprocessedCommits = _getUnprocessedCommits();
                m_logger.finer("About to process transactions: " + unprocessedCommits.toString());

                for (String txFilename : unprocessedCommits.values()) {
                    _processCommit(CommonDir.COMMIT.resolveToString(txFilename));
                }

                if (!unprocessedCommits.isEmpty()) {
                    m_maxTxNumProcessed = unprocessedCommits.lastKey();
                    m_logger.fine("Updating last processed transaction id: " + m_maxTxNumProcessed);
                }
                m_logger.fine(String.format("Finished processing [%d] existing commits.", unprocessedCommits.size()));
            }
        }

        private SortedMap<Integer, String> _getUnprocessedCommits() throws KeeperException, InterruptedException {
            // TODO: This is going to get really slow as the number of
            // transactions grows.
            // Instead we should have subdirectories and switch every few
            // minutes.
            ImmutableSortedMap.Builder<Integer, String> unprocessedCommitsBuilder = ImmutableSortedMap.naturalOrder();
            for (String txFilename : m_zk.getChildren(CommonDir.COMMIT.toString(), this)) {
                if (!txFilename.startsWith(COMMIT_FILENAME)) {
                    m_logger.severe("Unexpected filename in commit directory: " + txFilename);
                    continue;
                }

                int fileNumber = -1;
                try {
                    fileNumber = Integer.parseInt(txFilename.substring(COMMIT_FILENAME.length()));
                } catch (NumberFormatException e) {}

                if (fileNumber < 0) {
                    m_logger.severe("Unexpected filename in commit directory: " + txFilename);
                    continue;
                }

                if (fileNumber > m_maxTxNumProcessed) {
                    m_logger.finer("Adding " + txFilename + " to unprocessed txn set");
                    unprocessedCommitsBuilder.put(fileNumber, txFilename);
                } else {
                    m_logger.finer("Not processing " + txFilename + " because it was already processed");
                }
            }
            return unprocessedCommitsBuilder.build();
        }

        private void _processThisBankCommit(Transaction.ID txId, Predicate<ECPoint> thisBankSigVer,
                Predicate<ECPoint> otherBankSigVer, PvormUpdate otherBankUpdate)
                        throws KeeperException, InterruptedException {
            if (!txId.equals(m_currentTxId)) {
                m_logger.severe("Committed transaction involving this bank but was it was unexpected! (" + txId + ")");
                return;
            }

            if (!thisBankSigVer.test(m_bank.getPublicSigKey())) {
                m_logger.severe(
                        "Committed transaction involving this bank but signature did not verify! (" + txId + ")");
            } else if (!otherBankSigVer.test(m_currentOtherBank.getSigVerKey())) {
                m_logger.severe(
                        "Committed transaction involving this bank, but other bank's signature did not verify! (" + txId
                                + ")");
            } else {
                m_logger.fine("Processing committed transaction involving this bank.");
                if (m_runVerification) {
                    if (m_currentOtherBank.getPvorm().verifyUpdate(otherBankUpdate, m_executor)) {
                        m_currentOtherBank.getPvorm().applyLastVerifiedUpdate();
                    } else {
                        m_logger.warning("Transaction [" + m_currentTxId + "] failed to verify. Not applying.");
                    }
                } else {
                    m_logger.fine("  skipping verification, applying directly.");
                    m_currentOtherBank.getPvorm().applyUpdateWithoutVerification(otherBankUpdate);
                }
            }

            RequestCallback callback = m_requestCallbacks.remove(m_currentTxId);

            String txName = m_currentTxId.toString();
            _deleteFile(CommonDir.HEADER.resolve(txName));
            _deleteFile(CommonDir.SENDER_INFO.resolve(txName));
            _releaseLock();

            // Check if there's a success callback and call it. This will never
            // happen for the receiving bank, but that's ok. If a callback
            // throws
            // an exception, we just want to ignore it. It's the client's
            // problem.
            try {
                if (callback != null) callback.callSuccess();
            } catch (Exception e) {}
        }

        private void _processCommit(String txFilepath) throws KeeperException, InterruptedException {
            byte[] encodedTxn = m_zk.getData(txFilepath, null, null);
            Transaction trans = TopLevelSerializers.deserializeTransaction(m_params, encodedTxn);

            if (trans.getSourceBankKey().equals(m_bank.getPublicEncryptionKey())) {
                _processThisBankCommit(trans.getID(), trans::verifySenderSignature, trans::verifyReceiverSignature,
                        trans.getReceiverUpdate());
            } else if (trans.getDestBankKey().equals(m_bank.getPublicEncryptionKey())) {
                _processThisBankCommit(trans.getID(), trans::verifyReceiverSignature, trans::verifySenderSignature,
                        trans.getSenderUpdate());
            } else {
                m_logger.fine("Processing commit in file " + txFilepath);
                RemoteBank sourceBank = m_otherBanks.get(_getIdFromKey(trans.getSourceBankKey()));
                RemoteBank destBank = m_otherBanks.get(_getIdFromKey(trans.getDestBankKey()));
                // Verify the transaction and apply it.
                if (trans.verifySenderSignature(sourceBank.getSigVerKey())
                        && trans.verifyReceiverSignature(destBank.getSigVerKey())) {
                    if (m_runVerification) {
                        if (trans.verifyUpdates(sourceBank.getPvorm(), destBank.getPvorm(), m_executor)) {
                            m_logger.fine("Verified third-party transaction. Now applying.");
                            sourceBank.getPvorm().applyLastVerifiedUpdate();
                            destBank.getPvorm().applyLastVerifiedUpdate();
                        } else {
                            m_logger.severe("Committed third-party transaction failed to verify!");
                        }
                    } else {
                        m_logger.fine("Applying transaction without verification.");
                        sourceBank.getPvorm().applyUpdateWithoutVerification(trans.getSenderUpdate());
                        destBank.getPvorm().applyUpdateWithoutVerification(trans.getReceiverUpdate());
                    }
                } else {
                    m_logger.severe("Committed third-party transaction had invalid signatures.");
                }
            }

            for (Consumer<Transaction.ID> callback : m_globalTransactionCallbacks) {
                try {
                    callback.accept(trans.getID());
                } catch (Exception e) {
                    // These are user-supplied. It's they're problem if they
                    // throw an exception.
                }
            }
        }
    }
}
