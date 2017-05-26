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

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Random;
import java.util.function.Function;

import org.bouncycastle.math.ec.ECPoint;

import com.google.common.collect.ImmutableList;

/**
 * This class implements the contents of an ORAM entirely in plaintext so that a
 * bank can prepare transactions efficiently.
 */
public class PlaintextCircuitOram {
    private static final int NO_INDEX = Integer.MIN_VALUE;
    /* default */ static final BlockPosition FAKE_POSITION = new BlockPosition(NO_INDEX, NO_INDEX);

    // The tree depth is the number of layers of the tree BELOW the stash
    // (which is used as the root). That is, a tree consisting of only the
    // stash has depth 0, a tree with a stash and two leaves has depth 1, etc.
    private final int m_treeDepth;
    private final int m_numLeaves;
    private final int m_numBuckets;

    private final int m_bucketSize;
    private final int m_stashSize;

    private final Random m_rand;

    private final List<OramBucket<Block>> m_buckets;
    private final Map<ECPoint, Block> m_accountToBlock;

    private int m_size;
    private int m_evictLeafCounter;

    /**
     * Constructs a new plaintext ORAM map of ECPoints to integers with the
     * given depth, bucket size, and stash size using the provided source of
     * randomness. The ORAM is initialized completely empty with a capacity of
     * {@code 2^treeDepth}.
     *
     * @param treeDepth The depth of the tree BELOW the stash. That is, a tree
     *            of depth 0 is only the stash, a tree of depth 1 is the stash
     *            with two children (both leaves), etc.
     * @param bucketSize The number of data blocks that can fit in each bucket.
     *            The larger the number the more memory this ORAM will require
     *            per depth in the tree, but the smaller the stash will need to
     *            be for the same level of security.
     * @param stashSize The number of blocks that fit in the stash. If the stash
     *            overflows security will be violated. NOTE: For ease of
     *            implementation, we simply throw an error if the stash
     *            overflows.
     * @param rand The source of randomness used to associate blocks with
     *            leaves.
     * @throws IllegalArgumentException if any of {@code treeDepth},
     *             {@code bucketSize}, or {@code stashSize} are not positive.
     */
    public PlaintextCircuitOram(int treeDepth, int bucketSize, int stashSize, Random rand) {
        if (treeDepth < 1 || bucketSize < 0 || stashSize < 0)
            throw new IllegalArgumentException("Tree depth, bucket size, and stash size must all be positive.");

        m_treeDepth = treeDepth;
        m_numLeaves = (1 << m_treeDepth);
        m_numBuckets = (m_numLeaves * 2) - 1;

        m_bucketSize = bucketSize;
        m_stashSize = stashSize;

        m_rand = rand;

        // m_buckets has one more entry than we have logical buckets because of
        // the temp bucket.
        ImmutableList.Builder<OramBucket<Block>> bucketsBuilder = ImmutableList.builder();
        for (int i = 0; i < m_numBuckets + PvormUtils.STASH_INDEX; i++) {
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

        m_accountToBlock = new HashMap<>();

        m_size = 0;
        m_evictLeafCounter = 0;
    }

    public int getCapacity() {
        return m_numBuckets;
    }

    public int getSize() {
        return m_size;
    }

    public int getTreeDepth() {
        return m_treeDepth;
    }

    public int getBucketSize() {
        return m_bucketSize;
    }

    public int getStashSize() {
        return m_stashSize;
    }

    public int getNumberOfBuckets() {
        return m_numBuckets;
    }

    public Block getBlock(int bucketIndex, int blockIndex) {
        return m_buckets.get(bucketIndex).getBlock(blockIndex);
    }

    public boolean containsUser(ECPoint accountKey) {
        return m_accountToBlock.containsKey(accountKey);
    }

    public long getBalance(ECPoint accountKey) {
        Block block = m_accountToBlock.get(accountKey);
        if (block == null) throw new IllegalArgumentException("Attempted to read an account that does not exist.");
        if (block.getBucket() == null) throw new IllegalStateException("Block did not have bucket specified.");
        if (block.getLeafId() == NO_INDEX) throw new IllegalStateException("Block did not have leaf specified.");

        return block.getBalance();
    }

    /**
     * This inserts the new value into the deepest open slot towards a random
     * leaf in the ORAM without performing eviction on existing values.
     *
     * @param accountKey the public key of the new account to insiert.
     * @param balance the balance of the new account to insert (must be
     *            non-negative).
     * @throws IllegalArgumentException if the account already exists or the
     *             balance is negative.
     * @throws IllegalStateException if the ORAM is full or the insert results
     *             in an eviction failure.
     */
    public void insert(ECPoint accountKey, long balance) {
        if (m_accountToBlock.containsKey(accountKey))
            throw new IllegalArgumentException("Cannot add account that already exists.");
        if (balance < 0) throw new IllegalArgumentException("Cannot add new account with negative balance.");
        if (m_size >= m_numBuckets) throw new IllegalStateException("Oram is already full. Cannot add a new account.");

        int leafId = m_rand.nextInt(m_numLeaves);

        Block newBlock = new Block(accountKey, balance);
        newBlock.setLeafId(leafId);
        int indexInBucket = m_buckets.get(PvormUtils.TEMP_BUCKET_INDEX).add(newBlock);
        newBlock.setPosition(m_buckets.get(PvormUtils.TEMP_BUCKET_INDEX), PvormUtils.TEMP_BUCKET_INDEX, indexInBucket);

        m_accountToBlock.put(accountKey, newBlock);

        // Evict out an independent random leaf.
        _evict();

        m_size++;

        if (!m_buckets.get(PvormUtils.TEMP_BUCKET_INDEX).isEmpty()) {
            throw new IllegalStateException("Temp bucket contained block "
                    + m_buckets.get(PvormUtils.TEMP_BUCKET_INDEX).getBlock(0).toString());
        }
    }

    /**
     * Performs an update on this plaintext ORAM of the given account and
     * balance.
     *
     * @param accountKey the public key of the account to update.
     * @param balanceChange the amount by which to change the balance (can be
     *            negative).
     * @return a transcript describing exactly which blocks were moved where
     *         during the update. This is used by
     *         {@link solidus.state.pvorm.OwnedPvorm} to determine which swaps
     *         to perform.
     * @throws IllegalArgumentException if the account does not exist or the
     *             balance would become negative.
     * @throws IllegalStateException if something is misconfigured or if
     *             eviction fails to free enough space in the stash.
     */
    public UpdateTranscript update(ECPoint accountKey, long balanceChange) {
        Block block = m_accountToBlock.get(accountKey);

        if (block == null) throw new IllegalArgumentException("Attempted to update account that does not exist.");
        if (block.getBucket() == null) throw new IllegalStateException("Block did not have bucket specified.");
        if (block.getLeafId() == NO_INDEX) throw new IllegalStateException("Block did not have leaf specified.");

        block.updateBalance(balanceChange);

        int oldLeafId = block.getLeafId();
        BlockPosition oldBlockPosition = block.getPosition();

        block.getBucket().remove(block.getPosition().getBlockIndexInBucket());
        int newBucketIndex = m_buckets.get(PvormUtils.TEMP_BUCKET_INDEX).add(block);
        block.setPosition(m_buckets.get(PvormUtils.TEMP_BUCKET_INDEX), PvormUtils.TEMP_BUCKET_INDEX, newBucketIndex);
        block.setLeafId(m_rand.nextInt(m_numLeaves));

        List<Eviction> swapsWithTemp = _evict();

        if (!m_buckets.get(PvormUtils.TEMP_BUCKET_INDEX).isEmpty()) {
            throw new IllegalStateException("Temp index was not evicted. This means the stash was full!");
        }

        return new UpdateTranscript(oldLeafId, oldBlockPosition, swapsWithTemp);
    }

    /**
     * This performs a double eviction along two non-overlapping paths. The path
     * choice is deterministic and cycles through all leaves in a manner to
     * maximally avoid overlap.
     */
    private List<Eviction> _evict() {
        List<Eviction> trace = ImmutableList.of(_evictOnce(PvormUtils.reverseBits(m_treeDepth, 2 * m_evictLeafCounter)),
                _evictOnce(PvormUtils.reverseBits(m_treeDepth, 2 * m_evictLeafCounter + 1)));
        m_evictLeafCounter = (m_evictLeafCounter + 1) % (m_numLeaves / 2);
        return trace;
    }

    private Eviction _evictOnce(int leafId) {
        Block[] deepest = _prepareDeepest(leafId);
        int[] target = _prepareTarget(leafId, deepest);
        return _evictOnceFast(leafId, deepest, target);
    }

    private int _getMaxOverlapDepth(int leafId1, int leafId2) {
        int maxDepth = 0;
        int levelBit = 1 << (m_treeDepth - 1);
        int pathXor = leafId1 ^ leafId2;
        while (levelBit > 0 && (pathXor & levelBit) == 0) {
            maxDepth++;
            levelBit /= 2;
        }
        return maxDepth;
    }

    private int _getDepth(Block block) {
        int depth = -1;
        int bucketIdx = block.getPosition().getBucketIndex();
        while (bucketIdx > 0) {
            depth++;
            bucketIdx /= 2;
        }
        return depth;
    }

    private Block[] _prepareDeepest(final int leafId) {
        // We need to include a block for the temp bucket, the stash, and each
        // real level of the tree.
        Block[] deepest = new Block[m_treeDepth + PvormUtils.STASH_INDEX + 1];
        OramBucket<Block> tempBucket = m_buckets.get(PvormUtils.TEMP_BUCKET_INDEX);
        Function<Block, Integer> blockToDepth = (block) -> _getMaxOverlapDepth(leafId, block.getLeafId());

        Block src = tempBucket.argMax(blockToDepth);
        int goal = (src == null ? NO_INDEX : blockToDepth.apply(src));

        // We start by evicting from the temp block, which is resides at depth
        // -1.
        // Array indices are offset by one as a result.
        for (int i = -1; i <= m_treeDepth; i++) {
            if (goal >= i)
                deepest[i + 1] = src;
            else
                deepest[i + 1] = null;

            int bucketIdx = PvormUtils.getBucketIndex(m_treeDepth, leafId, i);
            Block maxBlock = m_buckets.get(bucketIdx).argMax(blockToDepth);
            int maxDepth = (maxBlock == null ? NO_INDEX : blockToDepth.apply(maxBlock));
            if (maxDepth > goal) {
                goal = maxDepth;
                src = maxBlock;
            }
        }

        return deepest;
    }

    private int[] _prepareTarget(int leafId, Block[] deepest) {
        int[] target = new int[m_treeDepth + PvormUtils.STASH_INDEX + 1];
        int dest = NO_INDEX;
        int src = NO_INDEX;
        // We start by evicting from the temp block, which is resides at depth
        // -1.
        // Array indices are offset by one as a result.
        for (int i = m_treeDepth; i >= -1; i--) {
            if (i == src) {
                target[i + 1] = dest;
                src = NO_INDEX;
                dest = NO_INDEX;
            } else {
                target[i + 1] = NO_INDEX;
            }

            int bucketIdx = PvormUtils.getBucketIndex(m_treeDepth, leafId, i);
            if (deepest[i + 1] != null
                    && (target[i + 1] != NO_INDEX || (dest == NO_INDEX && !m_buckets.get(bucketIdx).isFull()))) {
                src = _getDepth(deepest[i + 1]);
                dest = i;
            }
        }
        return target;
    }

    private Eviction _evictOnceFast(int leafId, Block[] deepest, int[] target) {
        ImmutableList.Builder<BlockPosition> swapsWithTempBuilder = ImmutableList.builder();

        Block hold = null;
        int dest = NO_INDEX;
        for (int i = -1; i <= m_treeDepth; i++) {
            BlockPosition holdPosition = null;
            BlockPosition writePosition = null;
            int bucketIdx = PvormUtils.getBucketIndex(m_treeDepth, leafId, i);
            OramBucket<Block> bucket = m_buckets.get(bucketIdx);

            Block toWrite = null;
            if (hold != null && i == dest) {
                toWrite = hold;
                hold = null;
                dest = NO_INDEX;
            }

            if (target[i + 1] != NO_INDEX) {
                hold = deepest[target[i + 1] + 1];
                if (bucket != hold.getBucket())
                    throw new IllegalStateException("Trying to evict block that is in the wrong bucket!");

                // Do not record removal from the temp block as a "swap".
                if (i > -1) {
                    holdPosition = hold.getPosition();
                }

                bucket.remove(hold.getPosition().getBlockIndexInBucket());
                hold.unsetPosition();

                dest = target[i + 1];
            }

            if (toWrite != null) {
                int newIndexInBucket = bucket.add(toWrite);
                toWrite.setPosition(bucket, bucketIdx, newIndexInBucket);

                writePosition = toWrite.getPosition();
                swapsWithTempBuilder.add(writePosition);
            }

            // When writing we'll always insert into the first open position,
            // but we might pull something out from farther out in the bucket.
            // This means that we have to record the write swap first.
            if (holdPosition != null && !holdPosition.equals(writePosition)) {
                swapsWithTempBuilder.add(holdPosition);
            }
        }
        return new Eviction(leafId, swapsWithTempBuilder.build());
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < m_buckets.size(); i++) {
            if (i > PvormUtils.STASH_INDEX && m_buckets.get(i).isEmpty()) continue;

            if (i != 0) sb.append("\n");
            sb.append(Integer.toString(i, 2)).append(": ").append(m_buckets.get(i));
        }
        return sb.toString();
    }

    public static class BlockPosition {
        private final int m_bucketIndex;
        private final int m_blockIndexInBucket;

        private BlockPosition(int bucketIndex, int blockIndexInBucket) {
            m_bucketIndex = bucketIndex;
            m_blockIndexInBucket = blockIndexInBucket;
        }

        public int getBucketIndex() {
            return m_bucketIndex;
        }

        public int getBlockIndexInBucket() {
            return m_blockIndexInBucket;
        }

        public boolean equals(int bucketIndex, int blockIndex) {
            return m_bucketIndex == bucketIndex && m_blockIndexInBucket == blockIndex;
        }

        @Override
        public boolean equals(Object o) {
            if (o == this) return true;
            if (!(o instanceof BlockPosition)) return false;

            BlockPosition b = (BlockPosition) o;
            return equals(b.m_bucketIndex, b.m_blockIndexInBucket);
        }

        @Override
        public int hashCode() {
            return Objects.hash(m_bucketIndex, m_blockIndexInBucket);
        }

        @Override
        public String toString() {
            return "(" + m_bucketIndex + "," + m_blockIndexInBucket + ")";
        }
    }

    public static class Eviction {
        private final int m_leafId;
        private final List<BlockPosition> m_swapsWithTemp;

        public Eviction(int leafId, List<BlockPosition> swapsWithTemp) {
            m_leafId = leafId;
            m_swapsWithTemp = ImmutableList.copyOf(swapsWithTemp);
        }

        public int getLeafId() {
            return m_leafId;
        }

        public List<BlockPosition> getSwapsWithTemp() {
            return m_swapsWithTemp;
        }
    }

    public static class UpdateTranscript {
        private final int m_leafId;
        private final BlockPosition m_initialPosition;
        private final List<Eviction> m_evictions;

        public UpdateTranscript(int leafId, BlockPosition initialPosition, List<Eviction> evictions) {
            m_leafId = leafId;
            m_initialPosition = initialPosition;
            m_evictions = ImmutableList.copyOf(evictions);
        }

        public int getLeafId() {
            return m_leafId;
        }

        public BlockPosition getInitialPosition() {
            return m_initialPosition;
        }

        public List<Eviction> getEvictions() {
            return m_evictions;
        }
    }

    public static class Block {
        private final ECPoint m_accountKey;

        private long m_balance;

        private OramBucket<Block> m_bucket;
        private BlockPosition m_position;
        private int m_leafId;

        private Block(ECPoint accountKey, long balance) {
            m_accountKey = accountKey;
            m_balance = balance;

            m_bucket = null;
            m_position = null;
            m_leafId = NO_INDEX;

            if (m_balance < 0) throw new IllegalArgumentException("All blocks must have non-negative balances.");
        }

        public ECPoint getAccountKey() {
            return m_accountKey;
        }

        public long getBalance() {
            return m_balance;
        }

        private void updateBalance(long balanceChange) {
            if (m_balance + balanceChange < 0)
                throw new IllegalArgumentException("Attempted to set balance to negative value.");
            m_balance += balanceChange;
        }

        private OramBucket<Block> getBucket() {
            return m_bucket;
        }

        private BlockPosition getPosition() {
            return m_position;
        }

        /**
         * Performs a functional update on the current position of the Block.
         * This creates a new BlockPosition object so the old one can be easily
         * saved.
         */
        private void setPosition(OramBucket<Block> bucket, int bucketIndex, int indexInBucket) {
            m_bucket = bucket;
            m_position = new BlockPosition(bucketIndex, indexInBucket);
        }

        private void unsetPosition() {
            m_bucket = null;
            m_position = null;
        }

        private int getLeafId() {
            return m_leafId;
        }

        private void setLeafId(int leafId) {
            m_leafId = leafId;
        }

        @Override
        public String toString() {
            return "(" + m_balance + "," + Integer.toBinaryString(m_leafId) + "," + m_position + ")";
        }
    }
}
