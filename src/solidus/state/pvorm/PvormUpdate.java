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

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Future;
import java.util.stream.Collectors;

import com.google.common.collect.ImmutableList;

import org.bouncycastle.crypto.ec.ECPair;
import org.bouncycastle.math.ec.ECPoint;

import solidus.io.SerialHelpers;
import solidus.io.SerialWriter;
import solidus.util.EncryptionParams;
import solidus.util.Utils;
import solidus.zkproofs.DoubleSwapProof;
import solidus.zkproofs.MaxwellRangeProof;
import solidus.zkproofs.PlaintextEqProof;

/**
 * This class creates an update specification for an encrypted PVORM that can be
 * published publicly without leaking information.
 */
public class PvormUpdate implements SerialWriter {
    private final int m_treeDepth;
    private final int m_bucketSize;
    private final int m_stashSize;

    private final ECPoint m_publicKey;

    private final List<Swap> m_preUpdateSwapList;

    private final ECPair m_encryptedAccountKey;
    private final ECPair m_encryptedBalanceChange;
    private final PlaintextEqProof m_accountKeyProof;
    private final MaxwellRangeProof m_maxwellRangeProof;

    private final List<Swap> m_postUpdateSwapList;

    private PvormUpdate(Builder builder) {
        m_treeDepth = builder.m_treeDepth;
        m_bucketSize = builder.m_bucketSize;
        m_stashSize = builder.m_stashSize;

        m_publicKey = builder.m_publicKey;

        m_preUpdateSwapList = builder.m_preUpdateSwapList.stream().map(Utils::getFuture)
                .collect(Collectors.collectingAndThen(Collectors.toList(), ImmutableList::copyOf));
        m_encryptedAccountKey = builder.m_encryptedAccountKey;
        m_encryptedBalanceChange = builder.m_encryptedBalanceChange;
        m_accountKeyProof = builder.m_accountKeyProof;
        m_maxwellRangeProof = builder.m_maxwellRangeProof;

        m_postUpdateSwapList = builder.m_postUpdateSwapList.stream().map(Utils::getFuture)
                .collect(Collectors.collectingAndThen(Collectors.toList(), ImmutableList::copyOf));
    }

    public ECPoint getPublicKey() {
        return m_publicKey;
    }

    public List<Swap> getPreUpdateSwaps() {
        return m_preUpdateSwapList;
    }

    public ECPair getEncryptedAccountKey() {
        return m_encryptedAccountKey;
    }

    public ECPair getEncryptedBalanceChange() {
        return m_encryptedBalanceChange;
    }

    public PlaintextEqProof getAccountKeyProof() {
        return m_accountKeyProof;
    }

    public MaxwellRangeProof getMaxwellRangeProof() {
        return m_maxwellRangeProof;
    }

    public List<Swap> getPostUpdateSwaps() {
        return m_postUpdateSwapList;
    }

    public boolean isValidPvormSize(int treeDepth, int bucketSize, int stashSize) {
        return m_treeDepth == treeDepth && m_bucketSize == bucketSize && m_stashSize == stashSize;
    }

    @Override
    public void serialWriteOut(OutputStream outStream, boolean compressPoints) throws IOException {
        SerialHelpers.writeInt(outStream, m_treeDepth);
        // The builder checks that these are no more than 255, so a single byte
        // is enough.
        outStream.write(m_bucketSize);
        outStream.write(m_stashSize);

        SerialHelpers.writeECPoint(outStream, m_publicKey, compressPoints);

        SerialHelpers.writeInt(outStream, m_preUpdateSwapList.size());
        for (Swap swap : m_preUpdateSwapList) {
            swap.serialWriteOut(outStream, compressPoints);
        }

        SerialHelpers.writeECPair(outStream, m_encryptedAccountKey, compressPoints);
        SerialHelpers.writeECPair(outStream, m_encryptedBalanceChange, compressPoints);

        m_accountKeyProof.serialWriteOut(outStream, compressPoints);

        if (m_maxwellRangeProof == null) {
            SerialHelpers.writeBoolean(outStream, false);
        } else {
            SerialHelpers.writeBoolean(outStream, true);
            m_maxwellRangeProof.serialWriteOut(outStream, compressPoints);
        }

        SerialHelpers.writeInt(outStream, m_postUpdateSwapList.size());
        for (Swap swap : m_postUpdateSwapList) {
            swap.serialWriteOut(outStream, compressPoints);
        }
    }

    public static PvormUpdate serialReadIn(InputStream inStream, EncryptionParams params) throws IOException {
        int treeDepth = SerialHelpers.readInt(inStream);
        int bucketSize = inStream.read();
        int stashSize = inStream.read();
        if (bucketSize < 0 || stashSize < 0) throw new EOFException();

        ECPoint publicKey = SerialHelpers.readECPoint(inStream, params);

        PvormUpdate.Builder builder = new PvormUpdate.Builder(treeDepth, bucketSize, stashSize, publicKey);

        int preUpdateSwapLength = SerialHelpers.readInt(inStream);
        for (int i = 0; i < preUpdateSwapLength; i++) {
            Swap swap = Swap.serialReadIn(inStream, params);
            builder.addPreUpdateSwap(CompletableFuture.completedFuture(swap));
        }

        builder.setEncryptedAccountKey(SerialHelpers.readECPair(inStream, params));
        builder.setEncryptedBalanceChange(SerialHelpers.readECPair(inStream, params));

        builder.setAccountKeyProof(PlaintextEqProof.serialReadIn(inStream, params));

        boolean hasRangeProof = SerialHelpers.readBoolean(inStream);
        if (hasRangeProof) builder.setMaxwellRangeProof(MaxwellRangeProof.serialReadIn(inStream, params));

        int postUpdateSwapLength = SerialHelpers.readInt(inStream);
        for (int i = 0; i < postUpdateSwapLength; i++) {
            Swap swap = Swap.serialReadIn(inStream, params);
            builder.addPostUpdateSwap(CompletableFuture.completedFuture(swap));
        }

        return builder.build();
    }

    @Override
    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof PvormUpdate)) return false;

        PvormUpdate update = (PvormUpdate) o;
        return (m_treeDepth == update.m_treeDepth) && (m_bucketSize == update.m_bucketSize)
                && (m_stashSize == update.m_stashSize) && Objects.equals(m_publicKey, update.m_publicKey)
                && Objects.equals(m_preUpdateSwapList, update.m_preUpdateSwapList)
                && Objects.equals(m_encryptedAccountKey, update.m_encryptedAccountKey)
                && Objects.equals(m_encryptedBalanceChange, update.m_encryptedBalanceChange)
                && Objects.equals(m_accountKeyProof, update.m_accountKeyProof)
                && Objects.equals(m_maxwellRangeProof, update.m_maxwellRangeProof)
                && Objects.equals(m_postUpdateSwapList, update.m_postUpdateSwapList);
    }

    @Override
    public int hashCode() {
        return Objects.hash(m_treeDepth, m_bucketSize, m_stashSize, m_publicKey, m_preUpdateSwapList,
                m_encryptedAccountKey, m_encryptedBalanceChange, m_accountKeyProof, m_maxwellRangeProof,
                m_postUpdateSwapList);
    }

    public static class Swap {
        private final int m_bucketIndex;
        private final int m_blockIndex;

        private final EncryptedPvorm.Block m_postSwapTemp;
        private final EncryptedPvorm.Block m_postSwapInPvorm;

        private final DoubleSwapProof m_proof;

        public Swap(int bucketIndex, int blockIndex, EncryptedPvorm.Block postSwapTemp,
                EncryptedPvorm.Block postSwapInPvorm, DoubleSwapProof proof) {
            m_bucketIndex = bucketIndex;
            m_blockIndex = blockIndex;

            m_postSwapTemp = postSwapTemp;
            m_postSwapInPvorm = postSwapInPvorm;

            m_proof = proof;

            if (blockIndex > 0xff) throw new IllegalArgumentException("Block index cannot be greater than 255.");
        }

        public int getBucketIndex() {
            return m_bucketIndex;
        }

        public int getBlockIndex() {
            return m_blockIndex;
        }

        public EncryptedPvorm.Block getPostSwapTemp() {
            return m_postSwapTemp;
        }

        public EncryptedPvorm.Block getPostSwapInPvorm() {
            return m_postSwapInPvorm;
        }

        public DoubleSwapProof getProof() {
            return m_proof;
        }

        public boolean isAtLocation(int bucketIndex, int blockIndex) {
            return m_bucketIndex == bucketIndex && m_blockIndex == blockIndex;
        }

        public void serialWriteOut(OutputStream outStream, boolean compressPoints) throws IOException {
            SerialHelpers.writeInt(outStream, m_bucketIndex);
            outStream.write(m_blockIndex);

            m_postSwapTemp.serialWriteOut(outStream, compressPoints);
            m_postSwapInPvorm.serialWriteOut(outStream, compressPoints);

            m_proof.serialWriteOut(outStream, compressPoints);
        }

        public static Swap serialReadIn(InputStream inStream, EncryptionParams params) throws IOException {
            int bucketIndex = SerialHelpers.readInt(inStream);
            int blockIndex = inStream.read();
            if (blockIndex < 0) throw new EOFException();

            EncryptedPvorm.Block postSwapTemp = EncryptedPvorm.Block.serialReadIn(inStream, params);
            EncryptedPvorm.Block postSwapInPvorm = EncryptedPvorm.Block.serialReadIn(inStream, params);

            DoubleSwapProof proof = DoubleSwapProof.serialReadIn(inStream, params);

            return new Swap(bucketIndex, blockIndex, postSwapTemp, postSwapInPvorm, proof);
        }

        @Override
        public boolean equals(Object o) {
            if (o == this) return true;
            if (!(o instanceof Swap)) return false;

            Swap swap = (Swap) o;
            return (m_bucketIndex == swap.m_bucketIndex) && (m_blockIndex == swap.m_blockIndex)
                    && Objects.equals(m_postSwapTemp, swap.m_postSwapTemp)
                    && Objects.equals(m_postSwapInPvorm, swap.m_postSwapInPvorm);
        }

        @Override
        public int hashCode() {
            return Objects.hash(m_bucketIndex, m_blockIndex, m_postSwapTemp, m_postSwapInPvorm);
        }
    }

    public static class Builder {
        private final int m_treeDepth;
        private final int m_bucketSize;
        private final int m_stashSize;

        private final ECPoint m_publicKey;

        private final List<Future<Swap>> m_preUpdateSwapList;
        private final List<Future<Swap>> m_postUpdateSwapList;

        private ECPair m_encryptedAccountKey;
        private ECPair m_encryptedBalanceChange;
        private PlaintextEqProof m_accountKeyProof;
        private MaxwellRangeProof m_maxwellRangeProof;

        private boolean m_isBuilt;

        public Builder(int treeDepth, int bucketSize, int stashSize, ECPoint publicKey) {
            m_treeDepth = treeDepth;
            m_bucketSize = bucketSize;
            m_stashSize = stashSize;

            m_publicKey = publicKey;

            m_preUpdateSwapList = new ArrayList<>();
            m_postUpdateSwapList = new ArrayList<>();

            m_encryptedAccountKey = null;
            m_encryptedBalanceChange = null;
            m_accountKeyProof = null;

            m_isBuilt = false;

            if (bucketSize > 0xff || stashSize > 0xff)
                throw new IllegalArgumentException("Bucket and stash sizes cannot exceed 255.");
        }

        public Builder addPreUpdateSwap(Future<Swap> swapFuture) {
            if (m_isBuilt) throw new IllegalStateException("Cannot update values after building");
            if (m_encryptedBalanceChange != null)
                throw new IllegalStateException("Cannot add pre-update swap after setting update");

            m_preUpdateSwapList.add(swapFuture);
            return this;
        }

        public Builder setEncryptedAccountKey(ECPair encryptedAccountKey) {
            if (m_isBuilt) throw new IllegalStateException("Cannot update values after building");
            if (m_encryptedAccountKey != null) throw new IllegalStateException("Cannot set account key twice");
            if (encryptedAccountKey == null) throw new NullPointerException("Expected non-null account key cipher");

            m_encryptedAccountKey = encryptedAccountKey;
            return this;
        }

        public Builder setEncryptedBalanceChange(ECPair encryptedBalanceChange) {
            if (m_isBuilt) throw new IllegalStateException("Cannot update values after building");
            if (m_encryptedBalanceChange != null) throw new IllegalStateException("Cannot set update twice");
            if (encryptedBalanceChange == null) throw new NullPointerException("Expected non-null update cipher");

            m_encryptedBalanceChange = encryptedBalanceChange;
            return this;
        }

        public Builder setAccountKeyProof(PlaintextEqProof accountKeyProof) {
            if (m_isBuilt) throw new IllegalStateException("Cannot update values after building");
            if (m_accountKeyProof != null) throw new IllegalStateException("Cannot set account key proof twice");
            if (accountKeyProof == null) throw new NullPointerException("Expected non-null account key proof cipher");

            m_accountKeyProof = accountKeyProof;
            return this;
        }

        public Builder setMaxwellRangeProof(MaxwellRangeProof maxwellRangeProof) {
            if (m_isBuilt) throw new IllegalStateException("Cannot update values after building");
            if (m_maxwellRangeProof != null) throw new IllegalStateException("Cannot set range proof twice");
            if (maxwellRangeProof == null) throw new NullPointerException("Expected non-null range proof cipher");

            m_maxwellRangeProof = maxwellRangeProof;
            return this;
        }

        public Builder addPostUpdateSwap(Future<Swap> swapFuture) {
            if (m_isBuilt) throw new IllegalStateException("Cannot update values after building");
            if (m_encryptedBalanceChange == null)
                throw new IllegalStateException("Cannot add post-update swap before setting update");

            m_postUpdateSwapList.add(swapFuture);
            return this;
        }

        public PvormUpdate build() {
            if (m_isBuilt) throw new IllegalStateException("Cannot build update twice");
            if (m_encryptedBalanceChange == null)
                throw new IllegalStateException("Cannot build an update before setting the update cipher");
            m_isBuilt = true;

            return new PvormUpdate(this);
        }
    }
}
