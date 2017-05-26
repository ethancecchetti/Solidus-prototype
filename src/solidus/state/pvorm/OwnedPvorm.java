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

package solidus.state.pvorm;

import com.google.common.collect.ImmutableList;
import org.bouncycastle.crypto.ec.ECPair;
import org.bouncycastle.math.ec.ECPoint;

import solidus.state.pvorm.PlaintextCircuitOram.BlockPosition;
import solidus.util.AbstractEncryptor;
import solidus.util.Decryptor;
import solidus.util.EncryptionParams;
import solidus.util.Encryptor;
import solidus.util.Utils;

import solidus.zkproofs.DoubleSwapProof;
import solidus.zkproofs.MaxwellRangeProof;
import solidus.zkproofs.PlaintextEqProof;

import java.math.BigInteger;
import java.util.Iterator;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.function.Consumer;

/**
 * This class contains the functionality for an PVORM owned by whoever can read
 * this object. An {@code OwnedPvorm} contains an encrypted ORAM and a plaintext
 * copy of the entire contents. The two are updated in tandem and produce a
 * {@link solidus.state.pvorm.PvormUpdate PvormUpdate} which can be verified and
 * applied to the encrypted ORAM with only access to the encryption and public
 * key.
 *
 * @author ethan@cs.cornell.edu
 */
public class OwnedPvorm {
    private final EncryptionParams m_params;

    private final int m_treeDepth;
    private final int m_bucketSize;
    private final int m_stashSize;

    private final ECPoint m_publicKey;
    private final BigInteger m_secretKey;

    private final Encryptor m_encryptor;
    private final Decryptor m_decryptor;

    private final PlaintextCircuitOram m_plainOram;
    private final EncryptedPvorm m_encryptedPvorm;

    // This constructor can only be called through the Builder.
    private OwnedPvorm(Builder builder, EncryptedPvorm encryptedPvorm) {
        m_params = builder.m_params;

        m_treeDepth = builder.m_treeDepth;
        m_bucketSize = builder.m_bucketSize;
        m_stashSize = builder.m_stashSize;

        m_publicKey = builder.m_publicKey;
        m_secretKey = builder.m_secretKey;

        m_encryptor = m_params.getEncryptor(m_publicKey);
        m_decryptor = m_params.getDecryptor(m_secretKey);

        m_plainOram = builder.m_plainOram;
        m_encryptedPvorm = encryptedPvorm;
    }

    public ECPoint getPublicKey() {
        return m_publicKey;
    }

    public BigInteger getSecretKey() {
        return m_secretKey;
    }

    public boolean containsUser(ECPoint accountKey) {
        return m_plainOram.containsUser(accountKey);
    }

    public long getBalance(ECPoint accountKey) {
        return m_plainOram.getBalance(accountKey);
    }

    public EncryptedPvorm getEncryptedPvorm() {
        return m_encryptedPvorm;
    }

    /**
     * Updates this PVORM by modifying the specified account's balance by the
     * specified amount. Both the account identifier and balance change must be
     * encrypted under this PVORM's public encryption key. The update then
     * produces a record of all modifications along with ZK proofs that
     * everything was performed properly and returns that record. The update may
     * or may not contain a range proof on the resulting account balance, as
     * specified by the {@code includeRangeProof} argument.
     *
     * This operation performs all modifications and proofs in the local thread,
     * which can be quite slow.
     *
     * @param encryptedAccountKey An El Gamal encryption of the identifier
     *            (public key) of the account whose balance this method should
     *            update, encrypted under this PVORM's public encryption key.
     * @param encryptedBalanceChange An El Gamal encryption of the balance
     *            change value, encrypted under this PVORM's public encryption
     *            key.
     * @param includeRangeProof Whether or not to include a range proof on the
     *            resulting account balance with the returned update proofs.
     * @return A record of all updated values and proofs that they were all
     *         updated properly.
     * @throws IllegalArgumentException If the specified account does not exist
     *             in this PVORM.
     * @see #update(ECPair, ECPair, boolean, ExecutorService)
     */
    public PvormUpdate update(final ECPair encryptedAccountKey, final ECPair encryptedBalanceChange,
            final boolean includeRangeProof) {
        return update(encryptedAccountKey, encryptedBalanceChange, includeRangeProof, null);
    }

    /**
     * Updates this PVORM by modifying the specified account's balance by the
     * specified amount. Both the account identifier and balance change must be
     * encrypted under this PVORM's public encryption key. The update then
     * produces a record of all modifications along with ZK proofs that
     * everything was performed properly and returns that record. The update may
     * or may not contain a range proof on the resulting account balance, as
     * specified by the {@code includeRangeProof} argument.
     *
     * This operation parallelizes a large amount of the proof generation using
     * the provided thread pool ({@code executor}). If no thread pool is
     * provided ({@code executor == null}), then all operations will be
     * performed in the current thread.
     *
     * @param encryptedAccountKey An El Gamal encryption of the identifier
     *            (public key) of the account whose balance this method should
     *            update, encrypted under this PVORM's public encryption key.
     * @param encryptedBalanceChange An El Gamal encryption of the balance
     *            change value, encrypted under this PVORM's public encryption
     *            key.
     * @param includeRangeProof Whether or not to include a range proof on the
     *            resulting account balance with the returned update proofs.
     * @param executor The thread pool to use to parallelize proof generation
     *            operations. Can be {@code null} if all operations should be
     *            performed in the current thread.
     * @return A record of all updated values and proofs that they were all
     *         updated properly.
     * @throws IllegalArgumentException If the specified account does not exist
     *             in this PVORM.
     * @see #update(ECPair, ECPair, boolean, ExecutorService)
     */
    public PvormUpdate update(final ECPair encryptedAccountKey, final ECPair encryptedBalanceChange,
            final boolean includeRangeProof, final ExecutorService executor) {
        final PvormUpdate.Builder updateBuilder = new PvormUpdate.Builder(m_treeDepth, m_bucketSize, m_stashSize,
                m_publicKey);

        final ECPoint accountKey = m_decryptor.decryptPoint(encryptedAccountKey);
        final long balanceChange = m_decryptor.decryptBalance(encryptedBalanceChange);
        final PlaintextCircuitOram.UpdateTranscript transcript = m_plainOram.update(accountKey, balanceChange);

        EncryptedPvorm.Block tempBlock = m_encryptedPvorm.getBlock(PvormUtils.TEMP_BUCKET_INDEX, 0);

        // Perform swaps with temp block and everything along the path
        // containing the actual block, actually swapping the real block;
        tempBlock = _performAllSwaps(tempBlock, transcript.getLeafId(),
                ImmutableList.of(transcript.getInitialPosition()), executor, updateBuilder::addPreUpdateSwap);

        updateBuilder.setEncryptedAccountKey(encryptedAccountKey).setEncryptedBalanceChange(encryptedBalanceChange);
        tempBlock = tempBlock.updateBalance(encryptedBalanceChange);
        final ECPair updateBlockAccountKey = tempBlock.getEncryptedKey();

        Future<PlaintextEqProof> accountKeyProof = Utils.submitJob(() -> PlaintextEqProof.buildProof(m_params,
                updateBlockAccountKey, encryptedAccountKey, m_publicKey, m_secretKey), executor);

        if (includeRangeProof) {
            final ECPair encryptedBalance = tempBlock.getEncryptedBalance();
            final long balance = m_decryptor.decryptBalance(encryptedBalance);

            MaxwellRangeProof rangeProof = MaxwellRangeProof.buildProof(m_params, encryptedBalance, balance,
                    m_publicKey, m_secretKey, executor);
            updateBuilder.setMaxwellRangeProof(rangeProof);
        }

        // Evict
        for (PlaintextCircuitOram.Eviction eviction : transcript.getEvictions()) {
            tempBlock = _performAllSwaps(tempBlock, eviction.getLeafId(), eviction.getSwapsWithTemp(), executor,
                    updateBuilder::addPostUpdateSwap);
        }

        m_encryptedPvorm.setBlock(PvormUtils.TEMP_BUCKET_INDEX, 0, tempBlock);

        updateBuilder.setAccountKeyProof(Utils.getFuture(accountKeyProof));

        return updateBuilder.build();
    }

    private EncryptedPvorm.Block _performAllSwaps(EncryptedPvorm.Block tempBlock, int leafId,
            Iterable<BlockPosition> realSwaps, ExecutorService executor,
            Consumer<Future<PvormUpdate.Swap>> swapConsumer) {
        final Iterator<BlockPosition> swapPositionIter = realSwaps.iterator();

        BlockPosition nextSwapPosition;
        if (swapPositionIter.hasNext())
            nextSwapPosition = swapPositionIter.next();
        else
            nextSwapPosition = PlaintextCircuitOram.FAKE_POSITION;

        for (int blockIndex = 0; blockIndex < m_stashSize; blockIndex++) {
            boolean doSwap = nextSwapPosition.equals(PvormUtils.STASH_INDEX, blockIndex);
            if (doSwap && swapPositionIter.hasNext()) {
                nextSwapPosition = swapPositionIter.next();
            }
            tempBlock = _performSwap(tempBlock, PvormUtils.STASH_INDEX, blockIndex, doSwap, executor, swapConsumer);
        }
        for (int depth = 1; depth <= m_treeDepth; depth++) {
            final int bucketIndex = PvormUtils.getBucketIndex(m_treeDepth, leafId, depth);
            for (int blockIndex = 0; blockIndex < m_bucketSize; blockIndex++) {
                boolean doSwap = nextSwapPosition.equals(bucketIndex, blockIndex);
                if (doSwap && swapPositionIter.hasNext()) {
                    nextSwapPosition = swapPositionIter.next();
                }
                tempBlock = _performSwap(tempBlock, bucketIndex, blockIndex, doSwap, executor, swapConsumer);
            }
        }
        return tempBlock;
    }

    private EncryptedPvorm.Block _performSwap(final EncryptedPvorm.Block tempBlock, final int bucketIndex,
            final int blockIndex, boolean doSwap, final ExecutorService executor,
            final Consumer<Future<PvormUpdate.Swap>> swapConsumer) {
        final EncryptedPvorm.Block encBlock = m_encryptedPvorm.getBlock(bucketIndex, blockIndex);

        final EncryptedPvorm.Block newEncBlock, newTempBlock;
        if (doSwap) {
            newEncBlock = tempBlock.reencrypt(m_encryptor);
            newTempBlock = encBlock.reencrypt(m_encryptor);
        } else {
            newEncBlock = encBlock.reencrypt(m_encryptor);
            newTempBlock = tempBlock.reencrypt(m_encryptor);
        }

        Callable<PvormUpdate.Swap> swapBuilder = () -> {
            DoubleSwapProof swapProof = DoubleSwapProof.buildProof(m_params, tempBlock, encBlock, newTempBlock,
                    newEncBlock, m_publicKey, m_secretKey, !doSwap);
            return new PvormUpdate.Swap(bucketIndex, blockIndex, newTempBlock, newEncBlock, swapProof);
        };

        swapConsumer.accept(Utils.submitJob(swapBuilder, executor));

        m_encryptedPvorm.setBlock(bucketIndex, blockIndex, newEncBlock);
        return newTempBlock;
    }

    /**
     * This class constructs a builder for an {@code OwnedPvorm} object. It
     * allows arbitrary account keys and balances to be inserted into the PVORM.
     *
     * When {@code build()} is called, the contents of the plaintext ORAM
     * structure are encrypted into an {@code EncryptedPvorm} object which will
     * thereafter be updated in tandem automatically.
     */
    public static class Builder {
        private final EncryptionParams m_params;
        private final BigInteger m_secretKey;
        private final ECPoint m_publicKey;

        private final int m_treeDepth;
        private final int m_bucketSize;
        private final int m_stashSize;

        private final PlaintextCircuitOram m_plainOram;

        private boolean m_isBuilt;

        public Builder(EncryptionParams params, BigInteger secretKey, int treeDepth, int bucketSize, int stashSize) {
            m_params = params;
            m_secretKey = secretKey;
            m_publicKey = m_params.getGenerator().multiply(m_secretKey).normalize();

            m_treeDepth = treeDepth;
            m_bucketSize = bucketSize;
            m_stashSize = stashSize;

            m_plainOram = new PlaintextCircuitOram(m_treeDepth, m_bucketSize, m_stashSize, m_params.getRandomSource());

            m_isBuilt = false;

            if (treeDepth < 1 || bucketSize < 0 || stashSize < 0)
                throw new IllegalArgumentException("Tree depth, bucket size, and stash size must all be positive.");
            if (bucketSize > 0xff || stashSize > 0xff)
                throw new IllegalArgumentException("Bucket and stash sizes cannot exceed 255.");
        }

        public void insert(ECPoint accountKey, long balance) {
            if (m_isBuilt) throw new IllegalStateException("Cannot add new account after building PVORM.");
            m_plainOram.insert(accountKey, balance);
        }

        public OwnedPvorm build() {
            return _build(m_params.getEncryptor(m_publicKey));
        }

        public OwnedPvorm fastBuildForTest() {
            return _build(new AbstractEncryptor(m_params, m_publicKey, false) {
                @Override
                public ECPair encryptZero() {
                    return new ECPair(m_params.getInfinity(), m_params.getInfinity());
                }
            });
        }

        private OwnedPvorm _build(Encryptor encryptor) {
            if (m_isBuilt) throw new IllegalStateException("Already built. Cannot build another PVORM.");
            m_isBuilt = true;

            EncryptedPvorm.Builder encPvormBuilder = new EncryptedPvorm.Builder(m_publicKey, m_treeDepth, m_bucketSize,
                    m_stashSize);

            // The temp bucket and stash are a different sizes than normal
            // buckets, so we need to populate them separately.
            for (int i = 0; i < PvormUtils.TEMP_BUCKET_SIZE; i++) {
                _setEncryption(encPvormBuilder, PvormUtils.TEMP_BUCKET_INDEX, i, encryptor);
            }
            for (int i = 0; i < m_stashSize; i++) {
                _setEncryption(encPvormBuilder, PvormUtils.STASH_INDEX, i, encryptor);
            }

            // This could take a while for a large PVORM as we may be encrypting
            // millions of values here.
            for (int i = PvormUtils.STASH_INDEX + 1; i < m_plainOram.getNumberOfBuckets()
                    + PvormUtils.STASH_INDEX; i++) {
                for (int j = 0; j < m_bucketSize; j++) {
                    _setEncryption(encPvormBuilder, i, j, encryptor);
                }
            }

            EncryptedPvorm encryptedPvorm = encPvormBuilder.build();
            return new OwnedPvorm(this, encryptedPvorm);
        }

        private void _setEncryption(EncryptedPvorm.Builder encPvormBuilder, int bucketIndex, int blockIndex,
                Encryptor encryptor) {
            final PlaintextCircuitOram.Block block = m_plainOram.getBlock(bucketIndex, blockIndex);
            final ECPair encryptedKey;
            final ECPair encryptedBalance;
            if (block == null) {
                encryptedKey = encryptor.encryptZero();
                encryptedBalance = encryptor.encryptZero();
            } else {
                encryptedKey = encryptor.encryptPoint(block.getAccountKey());
                encryptedBalance = encryptor.encryptBalance(block.getBalance());
            }
            encPvormBuilder.setValue(bucketIndex, blockIndex, encryptedKey, encryptedBalance);
        }
    }
}
