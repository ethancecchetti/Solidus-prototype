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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;

import org.bouncycastle.crypto.ec.ECPair;
import org.bouncycastle.math.ec.ECPoint;

import solidus.io.SerialHelpers;
import solidus.io.SerialWriter;
import solidus.state.pvorm.PvormUpdate.Swap;
import solidus.util.Decryptor;
import solidus.util.EncryptionParams;
import solidus.util.Encryptor;
import solidus.util.Utils;
import solidus.zkproofs.DoubleSwapProof;
import solidus.zkproofs.MaxwellRangeProof;
import solidus.zkproofs.PlaintextEqProof;

/**
 * This class contains an encrypted PVORM as it appears on the public ledger.
 * While verification operations can be internally parallelized (by providing a
 * thread pool), this class is NOT thread safe!
 *
 * @author ethan@cs.cornell.edu
 */
public class EncryptedPvorm implements SerialWriter {
    private final ECPoint m_publicKey;

    private final int m_treeDepth;
    private final int m_bucketSize;
    private final int m_stashSize;

    private final List<OramBucket<Block>> m_buckets;

    // Saves the most-recently-verified update as a ShadowPvorm to make it fast
    // to apply the update. Because one update's verification relies on all
    // previous updates, (successfully) verifying a new update will overwrite a
    // previous one and prevent it from being applied without re-verifying.
    private transient ShadowPvorm m_lastVerifiedShadowPvorm;

    private EncryptedPvorm(Builder builder) {
        m_publicKey = builder.m_publicKey;

        m_treeDepth = builder.m_treeDepth;
        m_bucketSize = builder.m_bucketSize;
        m_stashSize = builder.m_stashSize;

        m_buckets = ImmutableList.copyOf(builder.m_buckets);

        m_lastVerifiedShadowPvorm = null;
    }

    public ECPoint getPublicKey() {
        return m_publicKey;
    }

    public Block getBlock(int bucketIndex, int blockIndex) {
        return m_buckets.get(bucketIndex).getBlock(blockIndex);
    }

    /* default */ void setBlock(int bucketIndex, int blockIndex, Block block) {
        m_buckets.get(bucketIndex).set(blockIndex, block);
    }

    /**
     * Verifies the specified {@link solidus.state.pvorm.PvormUpdate
     * PvormUpdate} as it would be applied to the current state of this PVORM
     * and returns whether or not the verification succeeded. If the
     * verification succeeds, the update is saved and can be applied
     * immediately. If a future update is verified before applying this one,
     * this update will need to be re-verified in order to apply it.
     *
     * @param update The {@link solidus.state.pvorm.PvormUpdate PvormUpdate} to
     *            verify.
     * @return {@code true} if the update is valid, {@code false} otherwise.
     * @see #verifyUpdate(PvormUpdate, ExecutorService)
     */
    public boolean verifyUpdate(PvormUpdate update) {
        return verifyUpdate(update, null);
    }

    /**
     * Verifies the specified {@link solidus.state.pvorm.PvormUpdate
     * PvormUpdate} as it would be applied to the current state using the
     * specified {@code
     * ExecutorService} to parallelize verification. Like {@code
     * verifyUpdate()}, if the verification succeeds, the update is saved and
     * can be applied immediately. If a future update is verified before
     * applying this one, this update will need to be re-verified in order to
     * apply it.
     *
     * @param update The {@link solidus.state.pvorm.PvormUpdate PvormUpdate} to
     *            verify.
     * @param executor The {@code ExecutorService} to use to execute parallel
     *            verification tasks.
     * @return {@code true} if the update is valid, {@code false} otherwise.
     * @see #verifyUpdate(PvormUpdate)
     */
    public boolean verifyUpdate(PvormUpdate update, ExecutorService executor) {
        if (!update.isValidPvormSize(m_treeDepth, m_bucketSize, m_stashSize)) return false;
        if (!update.getPublicKey().equals(m_publicKey)) return false;

        ShadowPvorm shadowPvorm = new ShadowPvorm();
        List<Future<Boolean>> verificationList = new ArrayList<>();
        Block tempBlock = getBlock(PvormUtils.TEMP_BUCKET_INDEX, 0);
        for (Swap swap : update.getPreUpdateSwaps()) {
            verificationList.add(_scheduleVerification(swap, tempBlock, shadowPvorm, executor));
            tempBlock = swap.getPostSwapTemp();
            shadowPvorm.setBlock(swap.getBucketIndex(), swap.getBlockIndex(), swap.getPostSwapInPvorm());
        }

        final ECPair tempAccountKey = tempBlock.getEncryptedKey();
        final ECPair updateAccountKey = update.getEncryptedAccountKey();
        final PlaintextEqProof accountKeyProof = update.getAccountKeyProof();
        Callable<Boolean> accountKeyProofVerifier = () -> accountKeyProof.verify(tempAccountKey, updateAccountKey,
                m_publicKey);
        verificationList.add(Utils.submitJob(accountKeyProofVerifier, executor));

        tempBlock = tempBlock.updateBalance(update.getEncryptedBalanceChange());

        if (update.getMaxwellRangeProof() != null) {
            final ECPair tempEncryptedBalance = tempBlock.getEncryptedBalance();
            final MaxwellRangeProof balanceRangeProof = update.getMaxwellRangeProof();
            Callable<Boolean> rangeProofVerifier = () -> balanceRangeProof.verify(tempEncryptedBalance, m_publicKey);
            verificationList.add(Utils.submitJob(rangeProofVerifier, executor));
        }

        for (Swap swap : update.getPostUpdateSwaps()) {
            verificationList.add(_scheduleVerification(swap, tempBlock, shadowPvorm, executor));
            tempBlock = swap.getPostSwapTemp();
            shadowPvorm.setBlock(swap.getBucketIndex(), swap.getBlockIndex(), swap.getPostSwapInPvorm());
        }

        shadowPvorm.setBlock(PvormUtils.TEMP_BUCKET_INDEX, 0, tempBlock);

        if (verificationList.stream().allMatch(Utils::getFuture)) {
            m_lastVerifiedShadowPvorm = shadowPvorm;
            return true;
        } else {
            return false;
        }
    }

    private Future<Boolean> _scheduleVerification(Swap swap, Block tempBlock, ShadowPvorm shadowPvorm,
            ExecutorService executor) {
        Block inPvormBlock = shadowPvorm.getBlock(swap.getBucketIndex(), swap.getBlockIndex());
        return Utils.submitJob(new SwapVerifier(tempBlock, inPvormBlock, m_publicKey, swap), executor);
    }

    /**
     * Applies the update most recently verified against this PVORM. Some update
     * must have been successfully verified since the last application.
     *
     * @throws IllegalStateException If no update has been successfully verified
     *             against this PVORM since the last update was applied.
     */
    public void applyLastVerifiedUpdate() {
        if (m_lastVerifiedShadowPvorm == null) throw new IllegalStateException("No unapplied verified update");

        m_lastVerifiedShadowPvorm.flushUpdates();
        m_lastVerifiedShadowPvorm = null;
    }

    public void applyUpdateWithoutVerification(PvormUpdate update) {
        if (!update.isValidPvormSize(m_treeDepth, m_bucketSize, m_stashSize))
            throw new IllegalArgumentException("Update was for wrong-sized pvorm");
        if (!update.getPublicKey().equals(m_publicKey))
            throw new IllegalArgumentException("Update was encrypted with wrong public key");

        Block tempBlock = getBlock(PvormUtils.TEMP_BUCKET_INDEX, 0);
        for (Swap swap : update.getPreUpdateSwaps()) {
            tempBlock = swap.getPostSwapTemp();
            setBlock(swap.getBucketIndex(), swap.getBlockIndex(), swap.getPostSwapInPvorm());
        }

        tempBlock = tempBlock.updateBalance(update.getEncryptedBalanceChange());

        for (Swap swap : update.getPostUpdateSwaps()) {
            tempBlock = swap.getPostSwapTemp();
            setBlock(swap.getBucketIndex(), swap.getBlockIndex(), swap.getPostSwapInPvorm());
        }

        setBlock(PvormUtils.TEMP_BUCKET_INDEX, 0, tempBlock);
    }

    public Map<ECPoint, Long> decryptAll(EncryptionParams params, BigInteger secretKey) {
        if (!params.getGenerator().multiply(secretKey).equals(m_publicKey)) {
            throw new IllegalArgumentException(
                    "Secret key and params did not correspond to public key for this pvorm.");
        }

        Decryptor decryptor = params.getDecryptor(secretKey);

        ImmutableMap.Builder<ECPoint, Long> mapBuilder = ImmutableMap.builder();
        for (OramBucket<Block> bucket : m_buckets) {
            for (Block block : bucket) {
                ECPoint accountKey = decryptor.decryptPoint(block.getEncryptedKey());
                if (!accountKey.equals(params.getInfinity())) {
                    mapBuilder.put(accountKey, decryptor.decryptBalance(block.getEncryptedBalance()));
                }
            }
        }
        return mapBuilder.build();
    }

    public EncryptedPvorm duplicate() {
        Builder builder = new Builder(m_publicKey, m_treeDepth, m_bucketSize, m_stashSize);
        for (int i = 0; i < m_buckets.size(); i++) {
            OramBucket<Block> bucket = m_buckets.get(i);
            for (int j = 0; j < bucket.getCapacity(); j++) {
                builder._setValue(i, j, bucket.getBlock(j));
            }
        }
        return builder.build();
    }

    @Override
    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof EncryptedPvorm)) return false;

        EncryptedPvorm pvorm = (EncryptedPvorm) o;
        return Objects.equals(m_publicKey, pvorm.m_publicKey) && Objects.equals(m_buckets, pvorm.m_buckets);
    }

    @Override
    public int hashCode() {
        return Objects.hash(m_publicKey, m_buckets);
    }

    @Override
    public void serialWriteOut(OutputStream outStream, boolean compressPoints) throws IOException {
        SerialHelpers.writeECPoint(outStream, m_publicKey, compressPoints);
        SerialHelpers.writeInt(outStream, m_treeDepth);
        SerialHelpers.writeInt(outStream, m_bucketSize);
        SerialHelpers.writeInt(outStream, m_stashSize);

        for (OramBucket<Block> bucket : m_buckets) {
            if (!bucket.isFull())
                throw new IllegalStateException("Cannot serialize EncryptedPvorm with non-full buckets");

            for (Block block : bucket)
                block.serialWriteOut(outStream, compressPoints);
        }
    }

    public static EncryptedPvorm serialReadIn(InputStream inStream, EncryptionParams params) throws IOException {
        ECPoint publicKey = SerialHelpers.readECPoint(inStream, params);
        int treeDepth = SerialHelpers.readInt(inStream);
        int bucketSize = SerialHelpers.readInt(inStream);
        int stashSize = SerialHelpers.readInt(inStream);

        EncryptedPvorm.Builder builder = new Builder(publicKey, treeDepth, bucketSize, stashSize);

        int totalBucketCount = _getTotalBucketCount(treeDepth);
        for (int bucketIndex = 0; bucketIndex < totalBucketCount; bucketIndex++) {
            final int thisBucketSize;
            if (bucketIndex < PvormUtils.TEMP_BUCKET_INDEX)
                thisBucketSize = 0;
            else if (bucketIndex == PvormUtils.TEMP_BUCKET_INDEX)
                thisBucketSize = PvormUtils.TEMP_BUCKET_SIZE;
            else if (bucketIndex == PvormUtils.STASH_INDEX)
                thisBucketSize = stashSize;
            else
                thisBucketSize = bucketSize;

            for (int blockIndex = 0; blockIndex < thisBucketSize; blockIndex++) {
                builder._setValue(bucketIndex, blockIndex, Block.serialReadIn(inStream, params));
            }
        }
        return builder.build();
    }

    private static int _getTotalBucketCount(int treeDepth) {
        return 1 << (treeDepth + 1) - 1 + PvormUtils.STASH_INDEX;
    }

    /**
     * A single immutable block in the encrypted portion of a PVORM. A block
     * contains a pair of El Gamal ciphertexts: one for the account's public key
     * and the other for the account balance. To avoid concerns over update
     * conflicts, these blocks are immutable; any update must create a new
     * object.
     */
    public static class Block implements DoubleSwapProof.CipherPair {
        private final ECPair m_encryptedKey;
        private final ECPair m_encryptedBalance;

        private Block(ECPair encryptedKey, ECPair encryptedBalance) {
            m_encryptedKey = encryptedKey;
            m_encryptedBalance = encryptedBalance;
        }

        /**
         * Gets the ciphertext for the account key in this block.
         *
         * @return The account key ciphertext.
         * @see #getCipher1
         */
        public ECPair getEncryptedKey() {
            return m_encryptedKey;
        }

        /**
         * Gets the ciphertext for the account key in this block.
         *
         * @return The account key ciphertext.
         * @see #getEncryptedKey
         */
        @Override
        public ECPair getCipher1() {
            return getEncryptedKey();
        }

        /**
         * Gets the ciphertext for the account balance in this block.
         *
         * @return The account balance ciphertext.
         * @see #getCipher2
         */
        public ECPair getEncryptedBalance() {
            return m_encryptedBalance;
        }

        /**
         * Gets the ciphertext for the account balance in this block.
         *
         * @return The account balance ciphertext.
         * @see #getEncryptedBalance
         */
        @Override
        public ECPair getCipher2() {
            return getEncryptedBalance();
        }

        /**
         * Creates a new block that's ciphertexts are reencryptions of the
         * current block's ciphertext.
         *
         * @param encryptor An {@link Encryptor} to use for the reencryption.
         * @return A new {@code Block} encrypting the same values.
         */
        public Block reencrypt(Encryptor encryptor) {
            return new Block(encryptor.reencrypt(m_encryptedKey), encryptor.reencrypt(m_encryptedBalance));
        }

        /**
         * Constructs a new block with the same account ciphertext and balance
         * that homomorphically combines this block's balance ciphertext with
         * the provided balnce change cipher. This method does no verification.
         *
         * @param balanceChange An encryption of a balance change under the same
         *            encryption key as this block's ciphertext.
         * @return A new {@code Block} with the updated balance ciphertext.
         */
        public Block updateBalance(ECPair balanceChange) {
            ECPair newBalance = new ECPair(m_encryptedBalance.getX().add(balanceChange.getX()),
                    m_encryptedBalance.getY().add(balanceChange.getY()));
            return new Block(m_encryptedKey, newBalance);
        }

        @Override
        public boolean equals(Object o) {
            if (o == this) return true;
            if (!(o instanceof Block)) return false;

            Block b = (Block) o;
            return Objects.equals(m_encryptedKey, b.m_encryptedKey)
                    && Objects.equals(m_encryptedBalance, b.m_encryptedBalance);
        }

        @Override
        public int hashCode() {
            return Objects.hash(m_encryptedKey, m_encryptedBalance);
        }

        @Override
        public void serialWriteOut(OutputStream outStream, boolean compressPoints) throws IOException {
            SerialHelpers.writeECPair(outStream, m_encryptedKey, compressPoints);
            SerialHelpers.writeECPair(outStream, m_encryptedBalance, compressPoints);
        }

        public static Block serialReadIn(InputStream inStream, EncryptionParams params) throws IOException {
            ECPair encryptedKey = SerialHelpers.readECPair(inStream, params);
            ECPair encryptedBalance = SerialHelpers.readECPair(inStream, params);
            return new Block(encryptedKey, encryptedBalance);
        }
    }

    /**
     * Creates a builder object to assemble an {@code EncryptedPvorm}. The
     * builder can set arbitrary cells in the PVORM to arbitrary ciphertexts.
     * Once {@code build()} is called, all values are frozen into a final
     * {@code EncryptedPvorm} that can only be updated with a
     * {@link solidus.state.pvorm.PvormUpdate PvormUpdate} object.
     *
     * This should only be used during system initialization for each bank to
     * construct its own PVORM.
     */
    public static class Builder {
        private final ECPoint m_publicKey;

        private final int m_totalBlocks;

        private final int m_treeDepth;
        private final int m_bucketSize;
        private final int m_stashSize;

        private final List<OramBucket<Block>> m_buckets;

        private int m_blocksSet;

        private boolean m_isBuilt;

        public Builder(ECPoint publicKey, int treeDepth, int bucketSize, int stashSize) {
            m_publicKey = publicKey.normalize();

            // The number of non-stash buckets is 2^(treeDepth + 1) - 1
            // so the total number of blocks is that mins 1 (the root is the
            // stash) * bucket size + stash size + temp size.
            m_totalBlocks = ((1 << (treeDepth + 1)) - 2) * bucketSize + stashSize + PvormUtils.TEMP_BUCKET_SIZE;

            m_treeDepth = treeDepth;
            m_bucketSize = bucketSize;
            m_stashSize = stashSize;

            ImmutableList.Builder<OramBucket<Block>> bucketsBuilder = ImmutableList.builder();
            int bucketListLength = _getTotalBucketCount(treeDepth);
            for (int i = 0; i < bucketListLength; i++) {
                if (i < PvormUtils.TEMP_BUCKET_INDEX) {
                    bucketsBuilder.add(new OramBucket<>(0));
                } else if (i == PvormUtils.TEMP_BUCKET_INDEX) {
                    bucketsBuilder.add(new OramBucket<>(PvormUtils.TEMP_BUCKET_SIZE));
                } else if (i == PvormUtils.STASH_INDEX) {
                    bucketsBuilder.add(new OramBucket<>(m_stashSize));
                } else {
                    bucketsBuilder.add(new OramBucket<>(m_bucketSize));
                }
            }
            m_buckets = bucketsBuilder.build();

            m_blocksSet = 0;

            m_isBuilt = false;
        }

        public Builder setValue(int bucketIndex, int blockIndex, ECPair encryptedKey, ECPair encryptedBalance) {
            return _setValue(bucketIndex, blockIndex, new Block(encryptedKey, encryptedBalance));
        }

        private Builder _setValue(int bucketIndex, int blockIndex, Block block) {
            if (m_isBuilt) throw new IllegalStateException("Cannot set EncryptedPvorm.Builder values after building.");

            if (m_buckets.get(bucketIndex).isSet(blockIndex)) {
                throw new IllegalArgumentException(
                        "Cannot set the same block twice: (" + bucketIndex + "," + blockIndex + ")");
            }
            m_buckets.get(bucketIndex).set(blockIndex, block);
            m_blocksSet++;
            return this;
        }

        public EncryptedPvorm build() {
            if (m_isBuilt)
                throw new IllegalStateException("Cannot build two EncryptedPvorm objects with the same builder.");
            if (m_blocksSet != m_totalBlocks) {
                throw new IllegalStateException("Cannot build an encrypted PVORM without setting all blocks ("
                        + m_blocksSet + " of " + m_totalBlocks + " set).");
            }
            m_isBuilt = true;

            return new EncryptedPvorm(this);
        }
    }

    private static class SwapVerifier implements Callable<Boolean> {
        private final Block m_startTemp;
        private final Block m_startInPvorm;
        private final ECPoint m_publicKey;
        private final Swap m_swap;

        public SwapVerifier(Block startTemp, Block startInPvorm, ECPoint publicKey, Swap swap) {
            m_startTemp = startTemp;
            m_startInPvorm = startInPvorm;
            m_publicKey = publicKey;
            m_swap = swap;
        }

        @Override
        public Boolean call() {
            return m_swap.getProof().verify(m_startTemp, m_startInPvorm, m_swap.getPostSwapTemp(),
                    m_swap.getPostSwapInPvorm(), m_publicKey);
        }
    }

    /**
     * This class creates a copy-on-write style shadow PVORM that allows us to
     * "apply" updates during validation without requiring work for a rollback.
     * All updates are inserted into an overlay map, and lookups hit the overlay
     * map first and then fall back to the underlying PVORM.
     */
    private class ShadowPvorm {
        private final Map<Integer, OramBucket<Block>> m_overwritten;

        private ShadowPvorm() {
            m_overwritten = new HashMap<>();
        }

        /**
         * Returns the block associated with the given location. If the location
         * has been overwritten in this shadow PVORM, it will be the
         * most-recently-written value. Otherwise it will be the block in the
         * underlying PVORM.
         */
        public Block getBlock(int bucketIndex, int blockIndex) {
            OramBucket<Block> dirtyBucket = m_overwritten.get(bucketIndex);
            Block dirtyBlock = null;
            // If we've overwritten anything in the bucket, try to pull this
            // block out.
            if (dirtyBucket != null) {
                dirtyBlock = dirtyBucket.getBlock(blockIndex);
            }

            // Even if something in the bucket was overwritten, this block may
            // not have been, so always check and pull the block from the
            // underlying PVORM if needed.
            if (dirtyBlock == null) {
                dirtyBlock = EncryptedPvorm.this.getBlock(bucketIndex, blockIndex);
            }
            return dirtyBlock;
        }

        /**
         * Updates the specified block in this shadow pvorm. This will not
         * overwrite the underlying pvorm, but will layer the update on top of
         * that.
         */
        public void setBlock(int bucketIndex, int blockIndex, Block block) {
            OramBucket<Block> dirtyBucket = m_overwritten.get(bucketIndex);
            if (dirtyBucket == null) {
                int bucketSize = (bucketIndex == PvormUtils.STASH_INDEX ? m_stashSize : m_bucketSize);
                dirtyBucket = new OramBucket<Block>(bucketSize);
                m_overwritten.put(bucketIndex, dirtyBucket);
            }

            dirtyBucket.set(blockIndex, block);
        }

        /**
         * Flushes all pending updates to the underlying PVORM. This will
         * actually modify the underlying PVORM and clean out the overlay table
         * in this shadow object.
         */
        public void flushUpdates() {
            for (Map.Entry<Integer, OramBucket<Block>> indexAndBucket : m_overwritten.entrySet()) {
                int bucketIndex = indexAndBucket.getKey();
                OramBucket<Block> bucket = indexAndBucket.getValue();

                for (int blockIndex = 0; blockIndex < bucket.getCapacity(); blockIndex++) {
                    if (bucket.isSet(blockIndex)) {
                        m_buckets.get(bucketIndex).set(blockIndex, bucket.getBlock(blockIndex));
                    }
                }
            }
            m_overwritten.clear();
        }
    }
}
