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

package solidus.state;

import java.math.BigInteger;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;

import com.google.common.collect.ImmutableList;

import org.bouncycastle.crypto.ec.ECPair;
import org.bouncycastle.math.ec.ECPoint;

import solidus.state.pvorm.EncryptedPvorm;
import solidus.state.pvorm.OwnedPvorm;
import solidus.state.pvorm.PvormUpdate;
import solidus.trans.Transaction;
import solidus.trans.TransactionHeader;
import solidus.trans.TransactionRequest;
import solidus.util.Decryptor;
import solidus.util.EncryptionParams;
import solidus.util.Utils;
import solidus.zkproofs.MaxwellRangeProof;
import solidus.zkproofs.PlaintextEqDisKeyProof;
import solidus.zkproofs.PlaintextEqProof;
import solidus.zkproofs.SchnorrSignature;

/**
 * This class implements a local bank over which the current node has complete
 * control. It contains a complete copy of the bank's entire state, both
 * encrypted and in plaintext as well as secret decryption and signing keys.
 *
 * A {@code Bank} object provides the core funcitonality necessary to process
 * one bank's side of a transaction. The
 * {@link #generateHeader(TransactionRequest, ExecutorService) generateHeader}
 * method generates a transaction header from a user's request. The
 * {@link #sendTransaction(TransactionHeader, ExecutorService)
 * sendTransaction()} method processes a transaction from the sending bank's
 * perspective and generates appropriate updates and proofs. Finally, the
 * {@link #receiveTransaction(TransactionHeader, ExecutorService)
 * receiveTransaction()} method processes a transaction from the receiving
 * bank's perspective, including appropriate updates and proofs.
 *
 * All of the main operations are parallelizable if given an {@code
 * ExecutorService} which can accept tasks into a thread pool.
 *
 * @author fanz@cs.cornell.edu and ethan@cs.cornell.edu
 */
public class LocalBank {
    private final EncryptionParams m_params;

    private final BigInteger m_secretSigningKey;
    private final BigInteger m_secretDecryptionKey;

    private final ECPoint m_publicEncKey;
    private final ECPoint m_publicSigKey;

    private final OwnedPvorm m_pvorm;
    private final List<User> m_users;

    /**
     * Constructs a new local back using a PVORM of the specified size with the
     * given secret keys and populates it with the specified users, all with
     * balance 0. The capacity of the PVORM ({@code 2^treeDepth}) must be able
     * to hold the number of users specified.
     *
     * This method constructs a new PVORM with all of the users specified. That
     * PVORM is then used for all future transaction opertaions within this
     * bank.
     *
     * @param params The public parameter configuration
     * @param treeDepth The depth of the PVORM tree (the root is depth 0), must
     *            be in [1, 29].
     * @param bucketSize The size of buckets in the PVORM. Larger buckets impose
     *            a larger performance overhead but make stash overflow less
     *            likely. Recommended size: 3.
     * @param stashSize The size of the PVORM stash. Larger stashes impose a
     *            performance overhead but are less likely to overflow. The
     *            relationship is linear.
     * @param secretDecryptionKey The decryption key to use for this bank.
     * @param secretSigningKey The key to use when generating signatures.
     * @param users The set of users at this bank.
     * @throws IllegalArgumentException under the following circumstances:
     *             <ul>
     *             <li>If any of {@code treeDepth}, {@code bucketSize}, or
     *             {@code stashSize} are not positive.</li>
     *             <li>If {@code treeDepth > 30}, {@code bucketSize > 255}, or
     *             {@code stashSize > 255}.</li>
     *             <li>If the number of users exceeds the capacity of the PVORM
     *             tree ({@code 2^treeDepth}).</li>
     *             </ul>
     */
    public LocalBank(EncryptionParams params, int treeDepth, int bucketSize, int stashSize,
            BigInteger secretDecryptionKey, BigInteger secretSigningKey, List<User> users) {
        this(params, treeDepth, bucketSize, stashSize, secretDecryptionKey, secretSigningKey, users,
                Utils.buildRepeatList(0L, users.size()));
    }

    /**
     * (FOR TESTING ONLY) Constructs a new local bank including PVORM with a
     * given set of users and specified starting balances. The capacity of the
     * PVORM ({@code 2^treeDepth}) must be able to hold the number of users
     * specified.
     *
     * This method constructs a new PVORM with all of the users specified. That
     * PVORM is then used for all future transaction opertaions within this
     * bank.
     *
     * @param params The public parameter configuration
     * @param treeDepth The depth of the PVORM tree (the root is depth 0), must
     *            be in [1, 29].
     * @param bucketSize The size of buckets in the PVORM. Larger buckets impose
     *            a larger performance overhead but make stash overflow less
     *            likely. Recommended size: 3.
     * @param stashSize The size of the PVORM stash. Larger stashes impose a
     *            performance overhead but are less likely to overflow. The
     *            relationship is linear.
     * @param secretDecryptionKey The decryption key to use for this bank.
     * @param secretSigningKey The key to use when generating signatures.
     * @param users The set of users at this bank.
     * @param initBalances The initial balances of each user in the same order
     *            as {@code users}.
     * @throws IllegalArgumentException under the following circumstances:
     *             <ul>
     *             <li>If {@code users} and {@code initBalances} are not the
     *             same length.</li>
     *             <li>If any of {@code treeDepth}, {@code bucketSize}, or
     *             {@code stashSize} are not positive.</li>
     *             <li>If {@code treeDepth > 30}, {@code bucketSize > 255}, or
     *             {@code stashSize > 255}.</li>
     *             <li>If the number of users exceeds the capacity of the PVORM
     *             tree ({@code 2^treeDepth}).</li>
     *             </ul>
     *
     * @see #LocalBank(EncryptionParams, int, int, int, BigInteger, BigInteger,
     *      List)
     */
    public LocalBank(EncryptionParams params, int treeDepth, int bucketSize, int stashSize,
            BigInteger secretDecryptionKey, BigInteger secretSigningKey, List<User> users, List<Long> initBalances) {
        if (users.size() != initBalances.size())
            throw new IllegalArgumentException("Must provide the same number of users and balances");
        if (treeDepth < 1 || bucketSize < 0 || stashSize < 0)
            throw new IllegalArgumentException("Tree depth, bucket size, and stash size must all be positive.");
        if (treeDepth > 30) throw new IllegalArgumentException("Cannot support more than 2^30 accounts.");
        if (users.size() > 1 << treeDepth)
            throw new IllegalArgumentException("Provided more accounts than PVORM capacity");

        m_params = params;
        m_secretSigningKey = secretSigningKey;
        m_secretDecryptionKey = secretDecryptionKey;

        m_publicEncKey = m_params.getGenerator().multiply(m_secretDecryptionKey).normalize();
        m_publicSigKey = m_params.getGenerator().multiply(m_secretSigningKey).normalize();

        m_users = ImmutableList.copyOf(users);

        OwnedPvorm.Builder pvormBuilder = new OwnedPvorm.Builder(m_params, m_secretDecryptionKey, treeDepth, bucketSize,
                stashSize);

        for (int i = 0; i < users.size(); i++) {
            pvormBuilder.insert(users.get(i).getAccountKey(), initBalances.get(i));
        }

        m_pvorm = pvormBuilder.build();
    }

    /**
     * Gets the public encryption key for this bank.
     *
     * @return the public encryption key of this bank.
     */
    public ECPoint getPublicEncryptionKey() {
        return m_publicEncKey;
    }

    /**
     * Gets the public signature verification key for this bank.
     *
     * @return the public signature verification key of this bank.
     */
    public ECPoint getPublicSigKey() {
        return m_publicSigKey;
    }

    /**
     * Gets a snapshot copy of the public {@link EncryptedPvorm} of this bank at
     * the current time. This returns a copy of the {@link EncryptedPvorm} that
     * is no longer linked to this bank's internal state in any way. This method
     * can also be quite expensive as it needs to copy the entire encrypted
     * state of this bank.
     *
     * @return a copy of the current {@link EncryptedPvorm} of this bank.
     */
    public EncryptedPvorm getEncryptedPvorm() {
        return m_pvorm.getEncryptedPvorm().duplicate();
    }

    /**
     * Returns the list of users for this bank.
     *
     * Note: This method returns actual {@link User} objects that include the
     * users' private keys and thus allow the creation of transaction requests.
     * This is very useful for testing and benchmarking, but would need to be
     * changed before a realistic deployment.
     *
     * @return the list of users at this bank.
     */
    public List<User> getUsers() {
        return m_users;
    }

    /**
     * Gets the balance of a specific user based on that user's public key.
     *
     * @param userPublicKey The public key (identifier) of the user whose
     *            balance to get.
     * @return the balance of the specified user.
     * @throws IllegalArgumentException if this bank does not contain a user
     *             with the specified public key.
     */
    public long getBalance(ECPoint userPublicKey) {
        return m_pvorm.getBalance(userPublicKey);
    }

    /**
     * Takes a transaction request originating from one of this bank's users and
     * generates a transaction header that the receiving bank can use to process
     * the transaction. This method can be parallelized by providing an
     * {@code java.util.concurrent.ExecutorService}.
     *
     * @param request The transaction request from a user.
     * @param executor An {@code java.util.concurrent.ExecutorService} providing
     *            a thread pool to be used for parallelization. If {@code
     *        executor} is {@code null}, this operation runs single-threaded.
     * @return A new {@link TransactionHeader} for the specified transaction.
     * @throws IllegalArgumentException if the request's signature doesn't
     *             verify, is not from a user at this bank, the transaction
     *             value is negative, or the user is trying to send more money
     *             than it has.
     * @see #sendTransaction(TransactionHeader, ExecutorService)
     * @see #receiveTransaction(TransactionHeader, ExecutorService)
     */
    public TransactionHeader generateHeader(TransactionRequest request, ExecutorService executor) {
        if (!request.verifySignature()) throw new IllegalArgumentException("Request signature does not verify");

        Decryptor decryptor = m_params.getDecryptor(m_secretDecryptionKey);

        ECPoint sourceAccountKey = decryptor.decryptPoint(request.getSourceAccountCipher());
        if (!m_pvorm.containsUser(sourceAccountKey)) throw new IllegalArgumentException("Unknown source user!");

        ECPair txValueCipher = request.getValueCipher();
        long txValue = decryptor.decryptBalance(txValueCipher);
        long existingBalance = m_pvorm.getBalance(sourceAccountKey);
        if (existingBalance < txValue || txValue < 0) {
            throw new IllegalArgumentException(
                    "Invalid transaction value. Either negative or balance too low: " + txValue);
        }

        // Prove that the transaction value is non-negative.
        MaxwellRangeProof valueRangeProof = MaxwellRangeProof.buildProof(m_params, txValueCipher, txValue,
                m_publicEncKey, m_secretDecryptionKey, executor);

        // Reencrypt the transaction value cipher so we know the randomness
        // and prove that the reencryption was correct.
        BigInteger r1 = m_params.getRandomIndex();
        ECPair rerandValueCipher = new ECPair(m_params.getGenerator().multiply(BigInteger.valueOf(txValue))
                .add(m_publicEncKey.multiply(r1)).normalize(), m_params.getGenerator().multiply(r1).normalize());
        Future<PlaintextEqProof> proofOfReRandomize = Utils.submitJob(() -> PlaintextEqProof.buildProof(m_params,
                txValueCipher, rerandValueCipher, m_publicEncKey, m_secretDecryptionKey), executor);

        // Reencrypt the transaction value under the receiving bank's key with
        // known randomness
        // and prove that the reencryption was correct.
        BigInteger r2 = m_params.getRandomIndex();
        ECPair reencValueCipher = new ECPair(m_params.getGenerator().multiply(BigInteger.valueOf(txValue))
                .add(request.getDestBankKey().multiply(r2)).normalize(),
                m_params.getGenerator().multiply(r2).normalize());
        Future<PlaintextEqDisKeyProof> proofOfReencryption = Utils
                .submitJob(
                        () -> PlaintextEqDisKeyProof.buildProof(m_params, rerandValueCipher, reencValueCipher,
                                m_publicEncKey, request.getDestBankKey(), BigInteger.valueOf(txValue), r1, r2),
                executor);

        return new TransactionHeader(request, valueRangeProof, rerandValueCipher, reencValueCipher,
                Utils.getFuture(proofOfReRandomize), Utils.getFuture(proofOfReencryption));
    }

    /**
     * Processes the sending bank's portion of a transaction. This includes
     * updating the banks PVORM and generating all associated proofs. This
     * method can be parallelized by providing a thread pool.
     *
     * @param header The transaction header of the transaction to process.
     * @param executor An {@code java.util.concurrent.ExecutorService} providing
     *            a thread pool to be used for parallelization. If {@code
     *        executor} is {@code null}, this operation runs single-threaded.
     * @return A {@link Transaction.SenderInfo} object with the information from
     *         the sending bank in the transaction.
     * @throws IllegalArgumentException If the source bank public encryption key
     *             specified by {@code header} is not this bank's public
     *             encryption key.
     */
    public Transaction.SenderInfo sendTransaction(TransactionHeader header, ExecutorService executor) {
        TransactionRequest request = header.getRequest();
        if (!request.getSourceBankKey().equals(m_publicEncKey)) {
            throw new IllegalArgumentException("Requests was not sending from this bank.");
        }

        ECPair negatedTxValueCipher = new ECPair(request.getValueCipher().getX().negate(),
                request.getValueCipher().getY().negate());
        PvormUpdate update = m_pvorm.update(request.getSourceAccountCipher(), negatedTxValueCipher, true, executor);

        SchnorrSignature signature = SchnorrSignature.sign(m_params, m_secretSigningKey, header, update);

        return new Transaction.SenderInfo(header, update, signature);
    }

    /**
     * Processes the receiving bank's portion of a transaction. This includes
     * updating the banks PVORM and generating all associated proofs. This
     * method can be parallelized by providing a thread pool.
     *
     * @param header The transaction header of the transaction to process.
     * @param executor An {@code java.util.concurrent.ExecutorService} providing
     *            a thread pool to be used for parallelization. If {@code
     *        executor} is {@code null}, this operation runs single-threaded.
     * @return A {@link Transaction.SenderInfo} object with the information from
     *         the sending bank in the transaction.
     * @throws IllegalArgumentException If the destination bank public
     *             encryption key specified by {@code header} is not this bank's
     *             public encryption key.
     */
    public Transaction.ReceiverInfo receiveTransaction(TransactionHeader header, ExecutorService executor) {
        if (!header.getDestBankKey().equals(m_publicEncKey)) {
            throw new IllegalArgumentException("Request was not directed to this bank.");
        }

        // Verify that the value ciphers were properly reencrypted coming from
        // the sending bank
        // and that the final value is non-negative.
        TransactionRequest request = header.getRequest();
        ECPair originalValueCipher = request.getValueCipher();
        ECPair rerandValueCipher = header.getSenderRerandomizedValue();
        ECPair reencValueCipher = header.getReceiverValue();

        PlaintextEqProof proofOfReRandomize = header.getProofOfRerandomize();
        if (!proofOfReRandomize.verify(originalValueCipher, rerandValueCipher, header.getSourceBankKey())) {
            throw new RuntimeException("Proof of Re-Randomization doesn't verify");
        }

        PlaintextEqDisKeyProof proofOfReencryption = header.getProofOfReencryption();
        if (!proofOfReencryption.verify(rerandValueCipher, reencValueCipher, header.getSourceBankKey(),
                m_publicEncKey)) {
            throw new RuntimeException("Proof of Re-Encryptioned under peer bank's key doesn't verify");
        }

        // This is equivalent to verifying the range proof but way faster.
        if (m_params.getDecryptor(m_secretDecryptionKey).decryptBalance(reencValueCipher) < 0) {
            throw new IllegalStateException("Trying to send a negative balance.");
        }

        PvormUpdate update = m_pvorm.update(request.getDestAccountCipher(), reencValueCipher, false, executor);
        SchnorrSignature signature = SchnorrSignature.sign(m_params, m_secretSigningKey, update);
        return new Transaction.ReceiverInfo(update, signature);
    }
}
