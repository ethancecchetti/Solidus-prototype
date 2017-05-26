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

import java.util.List;
import java.util.Random;
import java.util.concurrent.TimeUnit;

import com.google.common.base.Stopwatch;
import com.google.common.collect.ImmutableList;
//import com.google.common.collect.SortedMultiset;
//import com.google.common.collect.TreeMultiset;

import org.bouncycastle.math.ec.ECPoint;

import solidus.state.pvorm.PlaintextCircuitOram;
import solidus.util.CryptoConstants;
import solidus.util.EncryptionParams;

public class PlaintextOramBenchmark {
    private static final int JIT_ITERATIONS = 50000;
    private static final int JIT_TREE_DEPTH = 4;
    private static final int JIT_BUCKET_SIZE = 4;
    private static final int JIT_STASH_SIZE = 100;

    private static final int WARMUP_ITERATIONS = 1 << 18;
    private static final int TEST_ITERATIONS = 1 << 20;

    private static final List<Integer> TREE_DEPTHS = ImmutableList.of(5, 10, 15, 20);
    private static final List<Integer> BUCKET_SIZES = ImmutableList.of(3, 4, 5);
    private static final int STASH_SIZE = 100;

    public static void main(String[] args) {
        Random rand = new Random(1);
        EncryptionParams params = EncryptionParams.newTestParams(rand, CryptoConstants.CURVE, CryptoConstants.DIGEST);

        List<ECPoint> keys = _buildKeyList(TREE_DEPTHS.stream().mapToInt(Integer::intValue).max().getAsInt(), params);

        PlaintextCircuitOram jitOram = new PlaintextCircuitOram(JIT_TREE_DEPTH, JIT_BUCKET_SIZE, JIT_STASH_SIZE, rand);
        for (int i = 0; i < (1 << JIT_TREE_DEPTH); i++)
            jitOram.insert(keys.get(i), 0);
        _benchmarkOram(jitOram, params, keys, JIT_ITERATIONS, false);

        for (int treeDepth : TREE_DEPTHS) {
            for (int bucketSize : BUCKET_SIZES) {
                PlaintextCircuitOram oram = new PlaintextCircuitOram(treeDepth, bucketSize, STASH_SIZE, rand);
                for (int i = 0; i < (1 << treeDepth); i++)
                    oram.insert(keys.get(i), 0);

                System.out.printf("\ntreeDepth: %d; bucketSize: %d\n", treeDepth, bucketSize);
                _benchmarkOram(oram, params, keys, WARMUP_ITERATIONS, false);
                _benchmarkOram(oram, params, keys, TEST_ITERATIONS, true);
            }
        }
    }

    private static List<ECPoint> _buildKeyList(int size, EncryptionParams params) {
        ImmutableList.Builder<ECPoint> keysBuilder = new ImmutableList.Builder<>();
        ECPoint lastKey = params.getInfinity();
        for (int i = 0; i < (1 << size); i++) {
            lastKey = lastKey.add(params.getGenerator());
            keysBuilder.add(lastKey);
        }
        return keysBuilder.build();
    }

    private static void _benchmarkOram(PlaintextCircuitOram oram, EncryptionParams params, List<ECPoint> keys,
            int iterations, boolean doPrint) {
        // SortedMultiset<Integer> stashSizeCounts = TreeMultiset.create();
        Stopwatch updateWatch = Stopwatch.createUnstarted();
        for (int iter = 0; iter < iterations; iter++) {
            ECPoint key = keys.get(iter % (1 << oram.getTreeDepth()));
            updateWatch.start();
            oram.update(key, 1);
            updateWatch.stop();
            // stashSizeCounts.add(oram.getStashedBlocksCount());
        }

        if (doPrint) {
            System.out.printf("  updates/ms: %.2f\n",
                    ((double) iterations / updateWatch.elapsed(TimeUnit.MILLISECONDS)));
                    // System.out.println(" maximum stash size: " +
                    // stashSizeCounts.lastEntry().getElement());

            // int[] totals = new int[stashSizeCounts.lastEntry().getElement() +
            // 1];
            // totals[totals.length - 1] = stashSizeCounts.count(totals.length -
            // 1);
            // for (int i = totals.length - 2; i >= 0; i--)
            // {
            // totals[i] = totals[i + 1] + stashSizeCounts.count(i);
            // }
            // for (int i = 0; i < totals.length; i++)
            // {
            // System.out.printf(" %d,%d\n", i, totals[i]);
            // }
        }
    }
}
