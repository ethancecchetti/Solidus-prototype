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

/* default */ class PvormUtils {
    public static final int TEMP_BUCKET_INDEX = 0;
    public static final int TEMP_BUCKET_SIZE = 1;
    public static final int STASH_INDEX = 1;

    public static int getBucketIndex(int totalTreeDepth, int leafId, int bucketDepth) {
        // There is one bucket with depth less than 1: the temp bucket.
        if (bucketDepth < 0)
            return TEMP_BUCKET_INDEX;
        // (leafId / 2^(totalTreeDepth - bucketDepth)) + 2^bucketDepth
        else
            return (leafId >> (totalTreeDepth - bucketDepth)) + (1 << bucketDepth);
    }

    public static int reverseBits(final int treeDepth, int val) {
        int result = 0;
        for (int i = 0; i < treeDepth; i++) {
            result <<= 1;
            result |= (val & 1);
            val >>= 1;
        }
        return result;
    }

    // This is a static constants file so it cannot be instantiated.
    private PvormUtils() {}
}
