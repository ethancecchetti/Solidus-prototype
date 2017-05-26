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

import java.util.Arrays;
import java.util.HashSet;
import java.util.Objects;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

import com.google.common.base.Stopwatch;

public class RawCircuitOram {
    private static final long WARMUP_ITERATIONS = 1L << 30;
    private static final long TEST_ITERATIONS = 1L << 32;
    // private static final long TEST_ITERATIONS = 4;

    private static final int MAX_TRACKED_STASH_SIZE = 1 << 8;

    public static final int NO_INDEX = Integer.MIN_VALUE;

    private static class Data {
        private final int m_id;
        private int m_leafId;
        private Bucket m_bucket;

        public Data(int id) {
            m_id = id;
        }

        public String toString(int capacity) {
            // return "(" + m_id + "," + Integer.toBinaryString(capacity +
            // m_leafId) + ")";
            return "(" + m_id + "," + m_leafId + ")";
        }
    }

    private static class Bucket {
        private final Data[] m_data;
        private int m_size;

        public Bucket(int bucketSize) {
            m_data = new Data[bucketSize];
            m_size = 0;
        }

        public boolean add(Data data) {
            for (int i = 0; i < m_data.length; i++) {
                if (m_data[i] == null) {
                    m_data[i] = data;
                    m_size++;
                    return true;
                } else if (data.equals(m_data[i])) {
                    return true;
                }
            }
            return false;
        }

        public boolean remove(Data data) {
            for (int i = 0; i < m_data.length; i++) {
                if (data.equals(m_data[i])) {
                    m_data[i] = null;
                    m_size--;
                    return true;
                }
            }
            return false;
        }

        private boolean isFull() {
            return m_size == m_data.length;
        }

        public void clear() {
            Arrays.fill(m_data, null);
        }
    }

    private static class DeepestInfo {
        private final int m_depth;
        private final Data m_data;

        private DeepestInfo(int depth, Data data) {
            m_depth = depth;
            m_data = data;
        }
    }

    private final int m_treeDepth;
    private final int m_numLeaves;
    private final int m_capacity;
    private final int m_bucketSize;

    private final Data[] m_data;
    private final Bucket[] m_buckets;
    private final Set<Data> m_stash;

    private final Random m_rand;

    private int m_nextEvictionLeaf;

    private final DeepestInfo[] m_deepestAry;
    private final int[] m_targetAry;

    private RawCircuitOram(int treeDepth, int logCapacity, int bucketSize, Random rand) {
        m_treeDepth = treeDepth;
        m_numLeaves = 1 << m_treeDepth;
        m_capacity = 1 << logCapacity;
        m_bucketSize = bucketSize;

        m_data = new Data[m_capacity];

        // m_buckets index 0 and 1 are not used to make bit-shifting math
        // easier.
        // Instead we 1-index the buckets starting from the root but absorb the
        // root into the stash (and thus start with index 2).
        // This means that we can get to a bucket's parent by dividing its index
        // by 2 (with no shenanigans).
        m_buckets = new Bucket[2 << m_treeDepth];
        for (int i = 2; i < m_buckets.length; i++) {
            m_buckets[i] = new Bucket(m_bucketSize);
        }

        m_stash = new HashSet<>();

        m_rand = rand;

        m_nextEvictionLeaf = 0;

        m_deepestAry = new DeepestInfo[m_treeDepth + 1];
        m_targetAry = new int[m_treeDepth + 1];
    }

    private int insert(int id) {
        Data data = m_data[id];
        if (data != null) {
            if (data.m_bucket != null) {
                data.m_bucket.remove(data);
                data.m_bucket = null;
            }
        } else {
            data = new Data(id);
            m_data[id] = data;
        }

        m_stash.add(data);
        data.m_leafId = m_rand.nextInt(m_numLeaves);

        _evict();

        return m_stash.size();
    }

    private int _reverseBits(int val) {
        int result = 0;
        for (int i = 0; i < m_treeDepth; i++) {
            result <<= 1;
            result |= (val & 1);
            val >>= 1;
        }
        return result;
    }

    private void _evict() {
        _evictOnce(_reverseBits(2 * m_nextEvictionLeaf));
        _evictOnce(_reverseBits((2 * m_nextEvictionLeaf) + 1));
        m_nextEvictionLeaf = (m_nextEvictionLeaf + 1) % (m_numLeaves / 2);
    }

    private void _evictOnce(int leafId) {
        _prepareDeepest(leafId);
        _prepareTarget(leafId, m_deepestAry);
        _evictOnceFast(leafId, m_deepestAry, m_targetAry);
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

    private int _getBucketIndex(int totalTreeDepth, int leafId, int bucketDepth) {
        // (leafId + 2^totalDepth) / 2^(totalDepth - bucketDepth)
        return (leafId + m_numLeaves) >>> (totalTreeDepth - bucketDepth);
    }

    private void _prepareDeepest(final int leafId) {
        // We need to include a block for the temp bucket, the stash, and each
        // real level of the tree.
        // DeepestInfo[] deepest = new DeepestInfo[m_treeDepth + 1];

        DeepestInfo src = null;
        int goal = NO_INDEX;
        Data stashData = null;
        for (Data data : m_stash) {
            int newGoal = _getMaxOverlapDepth(leafId, data.m_leafId);
            if (newGoal > goal) {
                stashData = data;
                goal = newGoal;
            }
        }
        if (goal > 0) {
            src = new DeepestInfo(0, stashData);
            m_deepestAry[0] = src;
        } else
            m_deepestAry[0] = null;

        // We start by evicting from the temp block, which is resides at depth
        // -1.
        // Array indices are offset by one as a result.
        for (int i = 1; i <= m_treeDepth; i++) {
            if (goal >= i)
                m_deepestAry[i] = src;
            else
                m_deepestAry[i] = null;

            int bucketIdx = _getBucketIndex(m_treeDepth, leafId, i);
            int maxDepth = NO_INDEX;
            Data newData = null;
            for (Data data : m_buckets[bucketIdx].m_data) {
                if (data == null) continue;
                int depth = _getMaxOverlapDepth(leafId, data.m_leafId);
                if (depth > maxDepth) {
                    maxDepth = depth;
                    newData = data;
                }
            }

            if (maxDepth > goal) {
                goal = maxDepth;
                src = new DeepestInfo(i, newData);
            }
        }

        // return deepest;
    }

    private void _prepareTarget(int leafId, DeepestInfo[] deepest) {
        // int[] target = new int[m_treeDepth + 1];
        int dest = NO_INDEX;
        int src = NO_INDEX;
        // We start by evicting from the temp block, which is resides at depth
        // -1.
        // Array indices are offset by one as a result.
        for (int i = m_treeDepth; i >= 0; i--) {
            if (i == src) {
                m_targetAry[i] = dest;
                src = NO_INDEX;
                dest = NO_INDEX;
            } else {
                m_targetAry[i] = NO_INDEX;
            }

            int bucketIdx = _getBucketIndex(m_treeDepth, leafId, i);
            if (deepest[i] != null && (m_targetAry[i] != NO_INDEX
                    || (dest == NO_INDEX && (i == 0 || !m_buckets[bucketIdx].isFull())))) {
                src = deepest[i].m_depth;
                dest = i;
            }
        }
        // return target;
    }

    private void _evictOnceFast(int leafId, DeepestInfo[] deepest, int[] target) {
        Data hold = null;
        int dest = target[0];
        if (dest != NO_INDEX) {
            hold = deepest[0].m_data;
            m_stash.remove(hold);
            hold.m_bucket = null;
        }

        for (int i = 1; i <= m_treeDepth; i++) {
            Data toWrite = null;
            if (hold != null && i == dest) {
                toWrite = hold;
                hold = null;
                dest = NO_INDEX;
            }

            int bucketIdx = _getBucketIndex(m_treeDepth, leafId, i);
            if (target[i] != NO_INDEX) {
                hold = deepest[target[i]].m_data;
                if (hold.m_bucket != m_buckets[bucketIdx]) throw new RuntimeException();

                hold.m_bucket.remove(hold);
                hold.m_bucket = null;

                dest = target[i];
            }

            if (toWrite != null) {
                m_buckets[bucketIdx].add(toWrite);
                toWrite.m_bucket = m_buckets[bucketIdx];
            }
        }
    }

    private void warmup() {
        System.out.println("Warmup starting");

        for (int i = 0; i < m_capacity; i++)
            insert(i);

        System.out.println("Filled " + m_capacity + " elements");

        for (long i = 0; i < WARMUP_ITERATIONS; i++) {
            insert((int) (i % m_capacity));

            if (i > 0 && i % (1 << 28) == 0) System.out.println("Warmup finished " + i + " iterations");
        }

        System.out.println("Finished warmup of " + WARMUP_ITERATIONS + " iterations");
    }

    private void test() {
        long[] stashSizeCounts = new long[MAX_TRACKED_STASH_SIZE];
        long overflowCount = 0;
        int maxSize = -1;

        Stopwatch testWatch = Stopwatch.createStarted();
        for (long i = 0; i < TEST_ITERATIONS; i++) {
            int size = insert((int) (i % m_capacity));
            if (size > maxSize && size < MAX_TRACKED_STASH_SIZE) maxSize = size;

            if (size < MAX_TRACKED_STASH_SIZE)
                stashSizeCounts[size]++;
            else
                overflowCount++;

            // printOram();

            if (i > 0 && i % (1 << 28) == 0) System.out.println("Finished " + i + " test iterations");
        }
        testWatch.stop();
        System.out.printf("Total testing time: %s (%.2f per ms)\n", testWatch,
                (double) TEST_ITERATIONS / testWatch.elapsed(TimeUnit.MILLISECONDS));

        long[] counts = new long[maxSize + 1];
        counts[counts.length - 1] = stashSizeCounts[counts.length - 1];
        for (int i = counts.length - 2; i >= 0; i--) {
            counts[i] = counts[i + 1] + stashSizeCounts[i];
        }
        for (int i = 0; i < counts.length; i++) {
            System.out.printf("%d,%d\n", i, counts[i]);
            // System.out.printf(" Stash size %3d: %7d\n", i, counts[i]);
        }
        if (overflowCount > 0) {
            System.out.println("Overflow: " + overflowCount);
        }
        System.out.println("max stash size: " + maxSize);
    }

    private void printOram() {
        System.out.println();
        System.out.print("Stash: ");
        m_stash.stream().map((data) -> data.toString(m_numLeaves)).forEach(System.out::print);
        System.out.println();

        for (int i = 2; i < m_buckets.length; i++) {
            System.out.print(Integer.toBinaryString(i) + ": ");
            Stream.of(m_buckets[i].m_data).filter(Objects::nonNull).map((data) -> data.toString(m_numLeaves))
                    .forEach(System.out::print);
            // m_buckets[i].elementStream().mapToObj((id) ->
            // m_data[id].toString(m_numLeaves)).forEach(BatchedPathOram::debugPrint);
            System.out.println();
        }
    }

    public static void main(String[] args) {
        int treeDepth = Integer.parseInt(args[0]);
        int logCapacity = Integer.parseInt(args[1]);
        int bucketSize = Integer.parseInt(args[2]);

        System.out.println("Bechmarking batched Path ORAM");

        RawCircuitOram batch = new RawCircuitOram(treeDepth, logCapacity, bucketSize, new Random(1234567890L));
        batch.warmup();
        batch.test();
    }
}
