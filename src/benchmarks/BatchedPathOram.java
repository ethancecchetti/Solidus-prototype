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
import java.util.PriorityQueue;
import java.util.Random;
import java.util.Set;
import java.util.stream.Stream;

import com.google.common.collect.SortedMultiset;
import com.google.common.collect.TreeMultiset;

public class BatchedPathOram {
    private static final boolean DEBUG_OUTPUT = false;

    private static final long WARMUP_ITERATIONS = 1 << 22;
    // private static final long WARMUP_ITERATIONS = 0;
    private static final long TEST_ITERATIONS = 1 << 26;
    // private static final long TEST_ITERATIONS = 10;

    private static final int BUCKET_SIZE = 4;

    private static class Data {
        private final int m_id;
        private int m_leafId;
        private Bucket m_bucket;

        public Data(int id) {
            m_id = id;
        }

        public String toString(int capacity) {
            return "(" + m_id + "," + Integer.toBinaryString(capacity + m_leafId) + ")";
        }
    }

    private static class Bucket {
        private final Data[] m_data;

        public Bucket() {
            m_data = new Data[BUCKET_SIZE];
        }

        public boolean add(Data data) {
            for (int i = 0; i < BUCKET_SIZE; i++) {
                if (m_data[i] == null) {
                    m_data[i] = data;
                    return true;
                } else if (data.equals(m_data[i])) {
                    return true;
                }
            }
            return false;
        }

        public boolean remove(Data data) {
            for (int i = 0; i < BUCKET_SIZE; i++) {
                if (data.equals(m_data[i])) {
                    m_data[i] = null;
                    return true;
                }
            }
            return false;
        }

        public void clear() {
            Arrays.fill(m_data, null);
        }
    }

    private class EvictionPath implements Comparable<EvictionPath> {
        private final Data m_data;
        private final int m_maxDepth;

        public EvictionPath(Data data, int evictionLeaf) {
            m_data = data;
            // debugPrintln(" EvictionPath for data " + m_data.m_id);

            int maxDepth = 0;
            int levelBit = 1 << (m_treeDepth - 1);
            int pathXor = evictionLeaf ^ data.m_leafId;
            // debugPrintln(" evictionLeaf: " +
            // Integer.toBinaryString(evictionLeaf + m_numLeaves));
            // debugPrintln(" data.m_leafId: " +
            // Integer.toBinaryString(data.m_leafId + m_numLeaves));
            // debugPrintln(" pathXor: " + String.format("%4s",
            // Integer.toBinaryString(pathXor)).replace(' ', '0'));
            while (levelBit > 0 && (pathXor & levelBit) == 0) {
                maxDepth++;
                levelBit /= 2;
            }
            m_maxDepth = maxDepth;
            // debugPrintln(" maxDepth: " + m_maxDepth);
        }

        public int getMaxDepth() {
            return m_maxDepth;
        }

        @Override
        public int compareTo(EvictionPath otherPath) {
            return -Integer.compare(m_maxDepth, otherPath.m_maxDepth);
        }
    }

    private final int m_treeDepth;
    private final int m_numLeaves;

    private final int m_batchSize;
    private final int m_capacity;

    private final int m_rejectThreshold;

    private final Data[] m_data;
    private final Bucket[] m_buckets;
    private final Set<Data> m_stash;

    private final Random m_rand;

    private BatchedPathOram(int treeDepth, int logCapacity, int batchSize, int rejectThreshold) {
        m_treeDepth = treeDepth;
        m_numLeaves = 1 << m_treeDepth;

        m_batchSize = batchSize;
        m_capacity = 1 << logCapacity;

        m_rejectThreshold = 1 << rejectThreshold;

        m_data = new Data[m_capacity];

        // m_buckets index 0 and 1 are not used to make bit-shifting math
        // easier.
        // Instead we 1-index the buckets starting from the root but absorb the
        // root into the stash (and thus start with index 2).
        // This means that we can get to a bucket's parent by dividing its index
        // by 2 (with no shenanigans).
        m_buckets = new Bucket[2 << m_treeDepth];
        for (int i = 2; i < m_buckets.length; i++) {
            m_buckets[i] = new Bucket();
        }

        m_stash = new HashSet<>();

        m_rand = new Random();

        // debugPrintln("Constructed batch betchmarker with capacity " +
        // m_capacity + " and tree depth " + m_treeDepth);
    }

    private int insert(int... ids) {
        // debugPrintln("Inserting " + ids.length + " elts: " +
        // Arrays.toString(ids));

        int[] oldLeafs = new int[ids.length];
        for (int i = 0; i < ids.length; i++) {
            Data data = m_data[ids[i]];
            if (data != null) {
                if (data.m_bucket != null) {
                    data.m_bucket.remove(data);
                    data.m_bucket = null;
                }
                oldLeafs[i] = data.m_leafId;
            } else {
                // debugPrintln(" Creating new data for id " + ids[i]);
                data = new Data(ids[i]);
                m_data[ids[i]] = data;
                oldLeafs[i] = m_rand.nextInt(m_numLeaves);
            }

            m_stash.add(data);
            data.m_leafId = m_rand.nextInt(m_numLeaves);
        }

        for (int leafId : oldLeafs)
            evict(leafId);

        // printOram();
        return m_stash.size();
    }

    private void evict(int leafId) {
        // debugPrintln(" Evicting along path " +
        // Integer.toBinaryString(m_numLeaves + leafId));

        PriorityQueue<EvictionPath> evictionQueue = new PriorityQueue<>();

        {
            int bucketId = m_numLeaves + leafId;
            while (bucketId > 1) {
                Bucket bucket = m_buckets[bucketId];
                for (int i = 0; i < bucket.m_data.length; i++) {
                    if (bucket.m_data[i] != null) {
                        evictionQueue.add(new EvictionPath(bucket.m_data[i], leafId));
                    }
                }
                // bucket.elementStream()
                // .mapToObj((val) -> new EvictionPath(m_data[val], leafId))
                // .forEach(evictionQueue::add);
                bucketId /= 2;
            }
            for (Data data : m_stash) {
                evictionQueue.add(new EvictionPath(data, leafId));
            }
            // m_stash.forEach((val) -> evictionQueue.add(new
            // EvictionPath(m_data[val], leafId)));
        }

        // debugPrintln(" Eviction queue of length: " + evictionQueue.size());

        {
            int bucketId = m_numLeaves + leafId;
            for (int depth = m_treeDepth; depth > 0; depth--) {
                // debugPrintln(" Populating bucket " + bucketId + " (depth " +
                // depth + ")");

                Bucket bucket = m_buckets[bucketId];
                bucket.clear();

                while (!evictionQueue.isEmpty()) {
                    EvictionPath path = evictionQueue.poll();
                    if (path.getMaxDepth() < depth || !bucket.add(path.m_data)) {
                        evictionQueue.add(path);
                        break;
                    }
                    path.m_data.m_bucket = bucket;
                }
                bucketId /= 2;
            }
            m_stash.clear();
            evictionQueue.stream().forEach((path) -> m_stash.add(path.m_data));
        }
    }

    private void warmup() {
        System.out.println("Warmup starting");

        for (int i = 0; i < m_capacity; i++)
            insert(i);

        System.out.println("Filled " + m_capacity + " elements");

        for (long i = 0; i < WARMUP_ITERATIONS; i++)
            insert((int) (i % m_capacity));

        System.out.println("Finished warmup of " + WARMUP_ITERATIONS + " iterations");
    }

    private void test() {
        SortedMultiset<Integer> stashSizeCounts = TreeMultiset.create();
        long rejections = 0;

        int nextId = 0;
        int[] ids = new int[m_batchSize];
        for (long i = 0; i < TEST_ITERATIONS; i++) {
            for (int j = 0; j < m_batchSize; j++) {
                int rejectionsThisRound = 0;
                while (conflicts(nextId, ids, j)) {
                    rejectionsThisRound++;
                    if (rejectionsThisRound > m_capacity) {
                        throw new RuntimeException(
                                "Rejected everything. Batch size is too large or threshold is too high");
                    }
                    nextId = (nextId + 1) % m_capacity;
                }
                rejections += rejectionsThisRound;
                ids[j] = nextId;
                nextId = (nextId + 1) % m_capacity;
            }

            stashSizeCounts.add(insert(ids));

            if (i > 0 && i % (1 << 20) == 0) System.out.println("Finished " + i + " test iterations");
        }

        int[] counts = new int[stashSizeCounts.lastEntry().getElement() + 1];
        counts[counts.length - 1] = stashSizeCounts.count(counts.length - 1);
        for (int i = counts.length - 2; i >= 0; i--) {
            counts[i] = counts[i + 1] + stashSizeCounts.count(i);
        }
        for (int i = 0; i < counts.length; i++) {
            System.out.printf("%d,%d\n", i, counts[i]);
            // System.out.printf(" Stash size %3d: %7d\n", i, counts[i]);
        }
        System.out.println("  Rejected " + rejections + " attempts");
        System.out.println("max stash size: " + stashSizeCounts.lastEntry().getElement());
    }

    private boolean conflicts(int nextId, int[] ids, int maxIdx) {
        for (int i = 0; i < maxIdx; i++) {
            int pathDiff = m_data[nextId].m_leafId ^ m_data[ids[i]].m_leafId;
            int levelBit = 1 << m_treeDepth;
            while (levelBit > m_rejectThreshold && (levelBit & pathDiff) == 0) {
                levelBit /= 2;
            }
            if (levelBit <= m_rejectThreshold) {
                // debugPrintln("Conflict found between new data " +
                // m_data[nextId].toString(m_numLeaves) + " and existing data "
                // + m_data[ids[i]].toString(m_numLeaves));
                return true;
            }
        }
        return false;
    }

    private void printOram() {
        debugPrintln();
        debugPrint("Stash: ");
        m_stash.stream().map((data) -> data.toString(m_numLeaves)).forEach(BatchedPathOram::debugPrint);
        debugPrintln();

        for (int i = 2; i < m_buckets.length; i++) {
            debugPrint(Integer.toBinaryString(i) + ": ");
            Stream.of(m_buckets[i].m_data).filter(Objects::nonNull).map((data) -> data.toString(m_numLeaves))
                    .forEach(BatchedPathOram::debugPrint);
            // m_buckets[i].elementStream().mapToObj((id) ->
            // m_data[id].toString(m_numLeaves)).forEach(BatchedPathOram::debugPrint);
            debugPrintln();
        }
    }

    private static void debugPrint(String s) {
        if (DEBUG_OUTPUT) System.out.print(s);
    }

    private static void debugPrintln(String s) {
        if (DEBUG_OUTPUT) System.out.println(s);
    }

    private static void debugPrintln() {
        if (DEBUG_OUTPUT) System.out.println();
    }

    public static void main(String[] args) {
        int treeDepth = Integer.parseInt(args[0]);
        int logCapacity = Integer.parseInt(args[1]);
        int batchSize = Integer.parseInt(args[2]);
        int rejectThreshold = Integer.parseInt(args[3]);

        System.out.println("Bechmarking batched Path ORAM");

        BatchedPathOram batch = new BatchedPathOram(treeDepth, logCapacity, batchSize, rejectThreshold);
        batch.warmup();
        batch.test();
    }
}
