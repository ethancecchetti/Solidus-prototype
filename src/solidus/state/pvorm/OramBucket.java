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

import java.util.Arrays;
import java.util.Iterator;
import java.util.Objects;
import java.util.function.Function;
import java.util.stream.Stream;

/**
 * The API on this looks a lot like {@code List<T>} and probably could be
 * implemented by using {@code AbstractList<T>}. However, I have chosen to
 * manually implement only this simplified interface because it allows blocks to
 * be placed at arbitrary locations within a bucket as will be the case in an
 * encrypted ORAM.
 *
 * @author ethan@cs.cornell.edu
 */
public class OramBucket<T> implements Iterable<T> {
    // We use an array and keep track of the index of things to aid with
    // the encrypted oram.
    private final T[] m_blocks;

    private int m_size;

    @SuppressWarnings("unchecked")
    public OramBucket(int capacity) {
        m_blocks = (T[]) new Object[capacity];
        m_size = 0;
    }

    public boolean isEmpty() {
        return m_size == 0;
    }

    public boolean isFull() {
        return m_size >= m_blocks.length;
    }

    public int getCapacity() {
        return m_blocks.length;
    }

    public int getSize() {
        return m_size;
    }

    public T getBlock(int index) {
        return m_blocks[index];
    }

    public int add(T block) {
        if (isFull()) throw new IllegalStateException("Cannot add a block, already full.");
        for (int i = 0; i < m_blocks.length; i++) {
            if (m_blocks[i] == null) {
                m_blocks[i] = block;
                m_size++;
                return i;
            }
        }
        throw new RuntimeException("The bucket was not full, but all of the cells were taken.");
    }

    public void set(int index, T block) {
        if (m_blocks[index] == null && block != null)
            m_size++;
        else if (m_blocks[index] != null && block == null) m_size--;
        m_blocks[index] = block;
    }

    public void remove(int index) {
        if (m_blocks[index] != null) m_size--;
        m_blocks[index] = null;
    }

    public boolean isSet(int index) {
        return m_blocks[index] != null;
    }

    public <S extends Comparable<S>> T argMax(Function<T, S> func) {
        boolean noneFound = true;
        T bestArg = null;
        S bestVal = null;
        for (T t : m_blocks) {
            if (t == null) continue;

            S newVal = func.apply(t);
            if (noneFound || bestVal.compareTo(newVal) < 0) {
                bestVal = newVal;
                bestArg = t;
                noneFound = false;
            }
        }
        return bestArg;
    }

    public Stream<T> stream() {
        return Stream.of(m_blocks).filter(Objects::nonNull);
    }

    /**
     * Returns an iterator of all blocks currently in this bucket. If the bucket
     * is not full, empty slots are omitted.
     */
    @Override
    public Iterator<T> iterator() {
        return stream().iterator();
    }

    @Override
    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof OramBucket)) return false;

        @SuppressWarnings("unchecked")
        OramBucket<T> bucket = (OramBucket<T>) o;
        return m_size == bucket.m_size && Arrays.equals(m_blocks, bucket.m_blocks);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(m_blocks);
    }

    @Override
    public String toString() {
        return Arrays.toString(m_blocks) + " (" + m_size + ")";
    }
}
