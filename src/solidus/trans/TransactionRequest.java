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
import java.math.BigInteger;
import java.time.Instant;
import java.util.Objects;

import org.bouncycastle.crypto.ec.ECPair;
import org.bouncycastle.math.ec.ECPoint;

import solidus.io.SerialHelpers;
import solidus.io.SerialWriter;
import solidus.util.EncryptionParams;
import solidus.zkproofs.ProofOfKnowledgeOfRep;

/**
 * This class represents a transaction request from a user to its bank. It
 * contains all of the details necessary to process the transaction including
 * the user's signature.
 *
 * @author ethan@cs.cornell.edu
 */
public class TransactionRequest implements SerialWriter {
    public static final TransactionRequest TERMINATION_REQUEST = new TransactionRequest(null, null, null);

    private final EncryptionParams m_params;
    private final Details m_details;
    private final ProofOfKnowledgeOfRep m_proof;

    private TransactionRequest(EncryptionParams params, Details details, ProofOfKnowledgeOfRep proof) {
        m_params = params;
        m_details = details;
        m_proof = proof;
    }

    /**
     * Constructs a new transaction request to transfer {@code value} from the
     * account controlled by {@code signerKey} to the account
     * {@code destAccountKey}. The accounts must be at the banks designated by
     * {@code sourceBankKey} and {@code destBankKey}, respectively, or the
     * transaction will be invalid.
     *
     * @param params the encryption parameters for this Solidus instance.
     * @param sourceBankKey the encryption key of the source bank.
     * @param destBankKey the encryption key of the destination bank.
     * @param destAccountKey the public verification key for the destination
     *            account.
     * @param value the value of assets to transfer
     * @param signerKey the private signing key of the sending account.
     * @return a new transaction request to transfer {@code value} from the
     *         account controlled by {@code signerKey} to the account
     *         {@code destAccountKey}.
     */
    public static TransactionRequest buildRequest(EncryptionParams params, ECPoint sourceBankKey, ECPoint destBankKey,
            ECPoint destAccountKey, long value, BigInteger signerKey) {
        Transaction.ID id = new Transaction.ID(Instant.now().getEpochSecond(), params.getRandomSource().nextLong());

        ECPair destAccountCipher = params.getEncryptor(destBankKey).encryptPoint(destAccountKey);
        ECPair valueCipher = params.getEncryptor(sourceBankKey).encryptBalance(value);

        Details details = new Details(id, sourceBankKey, destBankKey, destAccountCipher, valueCipher);

        BigInteger sigRandomness = params.getRandomIndex();
        ECPoint sigCipherX = params.getGenerator().multiply(signerKey).add(sourceBankKey.multiply(sigRandomness))
                .normalize();
        ECPoint sigCipherY = params.getGenerator().multiply(sigRandomness).normalize();
        ECPair sigCipher = new ECPair(sigCipherX, sigCipherY);

        ProofOfKnowledgeOfRep proof = ProofOfKnowledgeOfRep.buildProof(params, sigCipher, sourceBankKey, signerKey,
                sigRandomness, details.toByteArray());

        return new TransactionRequest(params, details, proof);
    }

    /**
     * @return the opaque identifier for this transaction.
     */
    public Transaction.ID getID() {
        return m_details.m_id;
    }

    /**
     * @return the source bank's public encryption key.
     */
    public ECPoint getSourceBankKey() {
        return m_details.m_sourceBankKey;
    }

    /**
     * @return the destination bank's public encryption key.
     */
    public ECPoint getDestBankKey() {
        return m_details.m_destBankKey;
    }

    /**
     * @return an encryption of the source account's public verification key
     *         under the source bank's encryption key.
     */
    public ECPair getSourceAccountCipher() {
        return m_proof.getCipher();
    }

    /**
     * @return an encryption of the destination account's public verification
     *         key under the destination bank's encryption key.
     */
    public ECPair getDestAccountCipher() {
        return m_details.m_destAccountCipher;
    }

    /**
     * @return an encryption of the transaction value as a positive integer
     *         encrypted under the source bank's public encryption key.
     */
    public ECPair getValueCipher() {
        return m_details.m_valueCipher;
    }

    /**
     * @return whether or not this transaction request has timed out based on
     *         the settings in the parameters supplied on
     *         construction/deserialization.
     */
    public boolean isValid() {
        return m_details.m_id.isValid(m_params.getTransactionTimeoutMillis());
    }

    /**
     * @return whether or not the signature on this transaction request is
     *         valid.
     */
    public boolean verifySignature() {
        return m_proof.verify(m_details.m_sourceBankKey, m_details);
    }

    @Override
    public void serialWriteOut(OutputStream outStream, boolean compressPoints) throws IOException {
        m_details.serialWriteOut(outStream, compressPoints);
        m_proof.serialWriteOut(outStream, compressPoints);
    }

    /**
     * Reserializes a {@code TransactionRequest} object from an
     * {@code InputStream}.
     *
     * @param inStream the input stream to read from
     * @param params the {@code EncryptionParams} to use for deserialization
     * @return a deserialized {@code TransactionRequest} object
     * @throws IOException if something goes wrong reading from {@code inStream}
     */
    public static TransactionRequest serialReadIn(InputStream inStream, EncryptionParams params) throws IOException {
        Details details = Details.serialReadIn(inStream, params);
        ProofOfKnowledgeOfRep proof = ProofOfKnowledgeOfRep.serialReadIn(inStream, params);

        return new TransactionRequest(params, details, proof);
    }

    @Override
    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof TransactionRequest)) return false;

        TransactionRequest req = (TransactionRequest) o;
        return Objects.equals(m_details, req.m_details) && Objects.equals(m_proof, req.m_proof);
    }

    @Override
    public int hashCode() {
        return Objects.hash(m_details, m_proof);
    }

    /**
     * Represents all details of the transaction aside from the signature and
     * sending account.
     */
    private static class Details implements SerialWriter {
        private final Transaction.ID m_id;

        private final ECPoint m_sourceBankKey;
        private final ECPoint m_destBankKey;

        private final ECPair m_destAccountCipher;
        private final ECPair m_valueCipher;

        private Details(Transaction.ID id, ECPoint sourceBankKey, ECPoint destBankKey, ECPair destAccountCipher,
                ECPair valueCipher) {
            m_id = id;

            m_sourceBankKey = sourceBankKey;
            m_destBankKey = destBankKey;

            m_destAccountCipher = destAccountCipher;
            m_valueCipher = valueCipher;
        }

        public static Details serialReadIn(InputStream inStream, EncryptionParams params) throws IOException {
            Transaction.ID id = Transaction.ID.serialReadIn(inStream);

            ECPoint sourceBankKey = SerialHelpers.readECPoint(inStream, params);
            ECPoint destBankKey = SerialHelpers.readECPoint(inStream, params);

            ECPair destAccountCipher = SerialHelpers.readECPair(inStream, params);
            ECPair valueCipher = SerialHelpers.readECPair(inStream, params);

            return new Details(id, sourceBankKey, destBankKey, destAccountCipher, valueCipher);
        }

        @Override
        public void serialWriteOut(OutputStream outStream, boolean compressPoints) throws IOException {
            m_id.serialWriteOut(outStream, compressPoints);

            SerialHelpers.writeECPoint(outStream, m_sourceBankKey, compressPoints);
            SerialHelpers.writeECPoint(outStream, m_destBankKey, compressPoints);

            SerialHelpers.writeECPair(outStream, m_destAccountCipher, compressPoints);
            SerialHelpers.writeECPair(outStream, m_valueCipher, compressPoints);
        }

        @Override
        public boolean equals(Object o) {
            if (o == this) return true;
            if (!(o instanceof Details)) return false;

            Details dtls = (Details) o;
            return Objects.equals(m_id, dtls.m_id) && Objects.equals(m_sourceBankKey, dtls.m_sourceBankKey)
                    && Objects.equals(m_destBankKey, dtls.m_destBankKey)
                    && Objects.equals(m_destAccountCipher, dtls.m_destAccountCipher)
                    && Objects.equals(m_valueCipher, dtls.m_valueCipher);
        }

        @Override
        public int hashCode() {
            return Objects.hash(m_id, m_sourceBankKey, m_destBankKey, m_destAccountCipher, m_valueCipher);
        }
    }
}
