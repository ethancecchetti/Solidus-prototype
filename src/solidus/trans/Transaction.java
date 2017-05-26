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

package solidus.trans;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;

import org.bouncycastle.crypto.ec.ECPair;
import org.bouncycastle.math.ec.ECPoint;

import solidus.io.SerialHelpers;
import solidus.io.SerialWriter;
import solidus.state.pvorm.EncryptedPvorm;
import solidus.state.pvorm.PvormUpdate;
import solidus.util.EncryptionParams;
import solidus.util.Utils;
import solidus.zkproofs.SchnorrSignature;

/**
 * This class contains a single complete Solidus transaction record. The record
 * includes a request, header, PVORM updates from both sending and receiving
 * banks, and signatures from both banks.
 *
 * @author ethan@cs.cornell.edu
 */
public class Transaction implements SerialWriter {
    private final SenderInfo m_senderInfo;
    private final ReceiverInfo m_receiverInfo;

    private final TransactionHeader m_header;

    /**
     * Constructs a new transaction from its component pieces: a
     * {@link SenderInfo} and a {@link ReceiverInfo}.
     *
     * @param senderInfo The sending bank's side of the transaction.
     * @param receiverInfo The receiving bank's side of the transaction.
     */
    public Transaction(SenderInfo senderInfo, ReceiverInfo receiverInfo) {
        m_senderInfo = senderInfo;
        m_receiverInfo = receiverInfo;

        m_header = m_senderInfo.getHeader();
    }

    /**
     * @return The transaction ID of this transaction.
     */
    public ID getID() {
        return m_senderInfo.getHeader().getRequest().getID();
    }

    /**
     * @return The sending bank's public encryption key.
     */
    public ECPoint getSourceBankKey() {
        return m_header.getSourceBankKey();
    }

    /**
     * @return The receiving bank's public encryption key.
     */
    public ECPoint getDestBankKey() {
        return m_header.getDestBankKey();
    }

    /**
     * @return The header of this transaction.
     */
    public TransactionHeader getHeader() {
        return m_header;
    }

    /**
     * @return The sending bank's PVORM update.
     */
    public PvormUpdate getSenderUpdate() {
        return m_senderInfo.getUpdate();
    }

    /**
     * @return The receiving bank's PVORM update.
     */
    public PvormUpdate getReceiverUpdate() {
        return m_receiverInfo.getUpdate();
    }

    /**
     * Verifies the sending bank's signature of the {@link SenderInfo} value in
     * this transaction using the provided verification key.
     *
     * @param verificationKey The public signature verification key to use when
     *            verifying the signature.
     * @return {@code true} if the signature verifies with the given key,
     *         {@code false} otherwise.
     */
    public boolean verifySenderSignature(ECPoint verificationKey) {
        return m_senderInfo.verifySignature(verificationKey);
    }

    /**
     * Verifies the receiving bank's signature of the {@link ReceiverInfo} value
     * in this transaction using the provided verification key.
     *
     * @param verificationKey The public signature verification key to use when
     *            verifying the signature.
     * @return {@code true} if the signature verifies with the given key,
     *         {@code false} otherwise.
     */
    public boolean verifyReceiverSignature(ECPoint verificationKey) {
        return m_receiverInfo.verifySignature(verificationKey);
    }

    /**
     * Verifies the PVORM updates of both the sending and receiving banks
     * against the provided {@link EncryptedPvorm} objects. While it does not
     * update the PVORM's, if successful, it sets the last verified update so
     * {@link EncryptedPvorm#applyLastVerifiedUpdate} can be used to apply the
     * updates to each PVORM individually.
     *
     * This method performs all verification in the local thread and may be
     * relatively slow.
     *
     * @param sourcePvorm The {@link EncryptedPvorm} of the sending bank prior to
     *            this transaction.
     * @param destPvorm The {@link EncryptedPvorm} of the receiving bank prior
     *            to this transaction.
     * @return {@code true} if both updates successeful verify on the given
     *         PVORMs, {@code false} otherwise.
     * @see #verifyUpdates(EncryptedPvorm, EncryptedPvorm, ExecutorService)
     */
    public boolean verifyUpdates(EncryptedPvorm sourcePvorm, EncryptedPvorm destPvorm) {
        return verifyUpdates(sourcePvorm, destPvorm, null);
    }

    /**
     * Verifies the PVORM updates of both the sending and receiving banks
     * against the provided {@link EncryptedPvorm} objects. While it does not
     * update the PVORM's, if successful, it sets the last verified update so
     * {@link EncryptedPvorm#applyLastVerifiedUpdate} can be used to apply the
     * updates to each PVORM individually.
     *
     * This method will parallelize verification using the provided thread pool.
     * If no thread pool is provided ({@code null} is given for the
     * {@code executor} argument), then all verification will be performed in
     * the local thread.
     *
     * @param sourcePvorm The {@link EncryptedPvorm} of the sending bank prior to
     *            this transaction.
     * @param destPvorm The {@link EncryptedPvorm} of the receiving bank prior
     *            to this transaction.
     * @param executor The thread pool to use to parallelize work, or
     *            {@code null} if running in single-threaded mode.
     * @return {@code true} if both updates successeful verify on the given
     *         PVORMs, {@code false} otherwise.
     * @see #verifyUpdates(EncryptedPvorm, EncryptedPvorm)
     */
    public boolean verifyUpdates(EncryptedPvorm sourcePvorm, EncryptedPvorm destPvorm, ExecutorService executor) {
        List<Future<Boolean>> verificationList = new ArrayList<>();

        if (!sourcePvorm.getPublicKey().equals(getSourceBankKey())
                || !destPvorm.getPublicKey().equals(getDestBankKey())) {
            return false;
        }

        // Verify that the transaction value is positive.
        verificationList.add(Utils.submitJob(
                () -> m_header.getValueRangeProof().verify(m_header.getRequest().getValueCipher(), getSourceBankKey()),
                executor));

        // Verify that everything was reencrypted properly.
        verificationList.add(
                Utils.submitJob(() -> m_header.getProofOfRerandomize().verify(m_header.getRequest().getValueCipher(),
                        m_header.getSenderRerandomizedValue(), getSourceBankKey()), executor));

        verificationList.add(Utils.submitJob(
                () -> m_header.getProofOfReencryption().verify(m_header.getSenderRerandomizedValue(),
                        m_header.getReceiverValue(), m_header.getSourceBankKey(), m_header.getDestBankKey()),
                executor));

        // Verify the two updates.
        ECPair negatedTransactionValue = new ECPair(m_header.getRequest().getValueCipher().getX().negate(),
                m_header.getRequest().getValueCipher().getY().negate());
        if (!getSenderUpdate().getEncryptedBalanceChange().equals(negatedTransactionValue)
                || !getSenderUpdate().getEncryptedAccountKey().equals(m_header.getRequest().getSourceAccountCipher())
                || !getReceiverUpdate().getEncryptedBalanceChange().equals(m_header.getReceiverValue())
                || !getReceiverUpdate().getEncryptedAccountKey().equals(m_header.getRequest().getDestAccountCipher())) {
            return false;
        }

        if (getSenderUpdate().getMaxwellRangeProof() == null) return false;

        return verificationList.stream().allMatch(Utils::getFuture)
                && sourcePvorm.verifyUpdate(getSenderUpdate(), executor)
                && destPvorm.verifyUpdate(getReceiverUpdate(), executor);
    }

    @Override
    public void serialWriteOut(OutputStream outStream, boolean compressPoints) throws IOException {
        m_senderInfo.serialWriteOut(outStream, compressPoints);
        m_receiverInfo.serialWriteOut(outStream, compressPoints);
    }

    public static Transaction serialReadIn(InputStream inStream, EncryptionParams params) throws IOException {
        SenderInfo senderInfo = SenderInfo.serialReadIn(inStream, params);
        ReceiverInfo receiverInfo = ReceiverInfo.serialReadIn(inStream, params);
        return new Transaction(senderInfo, receiverInfo);
    }

    @Override
    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof Transaction)) return false;

        Transaction trans = (Transaction) o;
        return Objects.equals(m_senderInfo, trans.m_senderInfo) && Objects.equals(m_receiverInfo, trans.m_receiverInfo);
    }

    @Override
    public int hashCode() {
        return Objects.hash(m_senderInfo, m_receiverInfo);
    }

    /**
     * Represents an opaque transaction id. The ID actually consists of a random
     * value and a timestamp which can be used to check if the transaction is
     * timed out, but the ID should be used as opaque (and thus has no means by
     * which to access the timestamp other than a timeout check).
     *
     * IDs are 16 bytes long and cannot conflict.
     *
     * @author ethan@cs.cornell.edu
     */
    public static class ID implements SerialWriter {
        /**
         * Deserializes a length 16 byte array into an {@code ID}.
         *
         * @param data the byte array to deserialize
         * @return the deserialized transaction ID
         * @throws IllegalArgumentException if {@code data} is not exactly 16
         *             bytes long.
         */
        public static ID fromBytes(byte[] data) {
            if (data.length != 16)
                throw new IllegalArgumentException("Transaction ID expected 16 bytes but received " + data.length);

            ByteBuffer buffer = ByteBuffer.allocate(16).put(data);
            return new ID(buffer.getLong(0), buffer.getLong(8));
        }

        public static ID serialReadIn(InputStream inStream) throws IOException {
            long timestamp = SerialHelpers.readLong(inStream);
            long rand = SerialHelpers.readLong(inStream);
            return new ID(timestamp, rand);
        }

        private final long m_timestamp;
        private final long m_nonce;

        /**
         * Constructs a new transaction ID from a timestamp and a random nonce.
         *
         * @param timestamp the current time in epoch seconds
         * @param nonce a random 8-bit nonce
         */
        public ID(long timestamp, long nonce) {
            m_timestamp = timestamp;
            m_nonce = nonce;
        }

        /**
         * Checks if the ID has timed out. The ID has timed out if the current
         * time is more than {@code timeout} seconds ahead of the timestamp
         * provided as part of this ID.
         *
         * @param timeout the number of seconds before this is considered timed
         *            out
         * @return whether or not this ID has timed out
         */
        public boolean isValid(long timeout) {
            long timeAgo = Instant.now().getEpochSecond() - m_timestamp;
            return timeAgo >= 0 && timeAgo < timeout;
        }

        @Override
        public boolean equals(Object o) {
            if (o == this) return true;
            if (!(o instanceof ID)) return false;

            ID id = (ID) o;
            return m_timestamp == id.m_timestamp && m_nonce == id.m_nonce;
        }

        @Override
        public int hashCode() {
            return Objects.hash(m_timestamp, m_nonce);
        }

        @Override
        public String toString() {
            byte[] rawBytes = ByteBuffer.allocate(16).putLong(m_timestamp).putLong(m_nonce).array();
            return Base64.getUrlEncoder().encodeToString(rawBytes);
        }

        @Override
        public void serialWriteOut(OutputStream outStream, boolean compressPoints) throws IOException {
            SerialHelpers.writeLong(outStream, m_timestamp);
            SerialHelpers.writeLong(outStream, m_nonce);
        }
    }

    /**
     * This class contains all information from the sending bank about a given
     * transaction. The sending bank is responsible for creating the transaction
     * header, updating its PVORM state, and signing its changes.
     */
    public static class SenderInfo implements SerialWriter {
        private final TransactionHeader m_header;
        private final PvormUpdate m_update;
        private final SchnorrSignature m_signature;

        public SenderInfo(TransactionHeader header, PvormUpdate update, SchnorrSignature signature) {
            m_header = header;
            m_update = update;
            m_signature = signature;
        }

        public TransactionHeader getHeader() {
            return m_header;
        }

        public PvormUpdate getUpdate() {
            return m_update;
        }

        public boolean verifySignature(ECPoint verificationKey) {
            return m_signature.verify(verificationKey, m_header, m_update);
        }

        @Override
        public void serialWriteOut(OutputStream outStream, boolean compressPoints) throws IOException {
            m_header.serialWriteOut(outStream, compressPoints);
            m_update.serialWriteOut(outStream, compressPoints);
            m_signature.serialWriteOut(outStream, compressPoints);
        }

        public static SenderInfo serialReadIn(InputStream inStream, EncryptionParams params) throws IOException {
            TransactionHeader header = TransactionHeader.serialReadIn(inStream, params);
            PvormUpdate update = PvormUpdate.serialReadIn(inStream, params);
            SchnorrSignature signature = SchnorrSignature.serialReadIn(inStream, params);

            return new SenderInfo(header, update, signature);
        }

        @Override
        public boolean equals(Object o) {
            if (o == this) return true;
            if (!(o instanceof SenderInfo)) return false;

            SenderInfo info = (SenderInfo) o;
            return Objects.equals(m_header, info.m_header) && Objects.equals(m_update, info.m_update)
                    && Objects.equals(m_signature, info.m_signature);
        }

        @Override
        public int hashCode() {
            return Objects.hash(m_header, m_update, m_signature);
        }
    }

    /**
     * This class contains all information from the receiving bank about a given
     * transaction. The receiving bank is responsible only for updating its
     * PVORM state, and signing its changes.
     */
    public static class ReceiverInfo implements SerialWriter {
        private final PvormUpdate m_update;
        private final SchnorrSignature m_signature;

        public ReceiverInfo(PvormUpdate update, SchnorrSignature signature) {
            m_update = update;
            m_signature = signature;
        }

        public PvormUpdate getUpdate() {
            return m_update;
        }

        public boolean verifySignature(ECPoint verificationKey) {
            return m_signature.verify(verificationKey, m_update);
        }

        @Override
        public void serialWriteOut(OutputStream outStream, boolean compressPoints) throws IOException {
            m_update.serialWriteOut(outStream, compressPoints);
            m_signature.serialWriteOut(outStream, compressPoints);
        }

        public static ReceiverInfo serialReadIn(InputStream inStream, EncryptionParams params) throws IOException {
            PvormUpdate update = PvormUpdate.serialReadIn(inStream, params);
            SchnorrSignature signature = SchnorrSignature.serialReadIn(inStream, params);

            return new ReceiverInfo(update, signature);
        }

        @Override
        public boolean equals(Object o) {
            if (o == this) return true;
            if (!(o instanceof ReceiverInfo)) return false;

            ReceiverInfo info = (ReceiverInfo) o;
            return Objects.equals(m_update, info.m_update) && Objects.equals(m_signature, info.m_signature);
        }

        @Override
        public int hashCode() {
            return Objects.hash(m_update, m_signature);
        }
    }
}
