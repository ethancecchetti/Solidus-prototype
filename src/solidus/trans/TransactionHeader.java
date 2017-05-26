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
import java.util.Objects;

import org.bouncycastle.crypto.ec.ECPair;
import org.bouncycastle.math.ec.ECPoint;

import solidus.io.SerialHelpers;
import solidus.io.SerialWriter;
import solidus.util.EncryptionParams;
import solidus.zkproofs.MaxwellRangeProof;
import solidus.zkproofs.PlaintextEqDisKeyProof;
import solidus.zkproofs.PlaintextEqProof;

public class TransactionHeader implements SerialWriter {
    private final TransactionRequest m_request;

    private final MaxwellRangeProof m_valueRangeProof;
    private final ECPair m_senderRerandomizedValue;
    private final ECPair m_receiverValue;
    private final PlaintextEqProof m_proofOfRerandomize;
    private final PlaintextEqDisKeyProof m_proofOfReencryption;

    public TransactionHeader(TransactionRequest request, MaxwellRangeProof valueRangeProof,
            ECPair senderRerandomizedValue, ECPair receiverValue, PlaintextEqProof proofOfRerandomize,
            PlaintextEqDisKeyProof proofOfReencryption) {
        m_request = request;

        m_valueRangeProof = valueRangeProof;
        m_senderRerandomizedValue = senderRerandomizedValue;
        m_receiverValue = receiverValue;
        m_proofOfRerandomize = proofOfRerandomize;
        m_proofOfReencryption = proofOfReencryption;
    }

    public ECPoint getSourceBankKey() {
        return m_request.getSourceBankKey();
    }

    public ECPoint getDestBankKey() {
        return m_request.getDestBankKey();
    }

    public TransactionRequest getRequest() {
        return m_request;
    }

    public MaxwellRangeProof getValueRangeProof() {
        return m_valueRangeProof;
    }

    public ECPair getSenderRerandomizedValue() {
        return m_senderRerandomizedValue;
    }

    public ECPair getReceiverValue() {
        return m_receiverValue;
    }

    public PlaintextEqProof getProofOfRerandomize() {
        return m_proofOfRerandomize;
    }

    public PlaintextEqDisKeyProof getProofOfReencryption() {
        return m_proofOfReencryption;
    }

    public boolean verifyProofs() {
        return m_request.verifySignature() && m_valueRangeProof.verify(m_request.getValueCipher(), getSourceBankKey())
                && m_proofOfRerandomize.verify(m_request.getValueCipher(), m_senderRerandomizedValue,
                        getSourceBankKey())
                && m_proofOfReencryption.verify(m_senderRerandomizedValue, m_receiverValue, getSourceBankKey(),
                        getDestBankKey());
    }

    @Override
    public void serialWriteOut(OutputStream outStream, boolean compressPoints) throws IOException {
        m_request.serialWriteOut(outStream, compressPoints);

        m_valueRangeProof.serialWriteOut(outStream, compressPoints);

        SerialHelpers.writeECPair(outStream, m_senderRerandomizedValue, compressPoints);
        SerialHelpers.writeECPair(outStream, m_receiverValue, compressPoints);

        m_proofOfRerandomize.serialWriteOut(outStream, compressPoints);
        m_proofOfReencryption.serialWriteOut(outStream, compressPoints);
    }

    public static TransactionHeader serialReadIn(InputStream inStream, EncryptionParams params) throws IOException {
        TransactionRequest request = TransactionRequest.serialReadIn(inStream, params);

        MaxwellRangeProof valueRangeProof = MaxwellRangeProof.serialReadIn(inStream, params);

        ECPair senderRerandomizedValue = SerialHelpers.readECPair(inStream, params);
        ECPair receiverValue = SerialHelpers.readECPair(inStream, params);

        PlaintextEqProof proofOfRerandomize = PlaintextEqProof.serialReadIn(inStream, params);
        PlaintextEqDisKeyProof proofOfReencryption = PlaintextEqDisKeyProof.serialReadIn(inStream, params);

        return new TransactionHeader(request, valueRangeProof, senderRerandomizedValue, receiverValue,
                proofOfRerandomize, proofOfReencryption);
    }

    @Override
    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof TransactionHeader)) return false;

        TransactionHeader hd = (TransactionHeader) o;
        return Objects.equals(m_request, hd.m_request) && Objects.equals(m_valueRangeProof, hd.m_valueRangeProof)
                && Objects.equals(m_senderRerandomizedValue, hd.m_senderRerandomizedValue)
                && Objects.equals(m_receiverValue, hd.m_receiverValue)
                && Objects.equals(m_proofOfRerandomize, hd.m_proofOfRerandomize)
                && Objects.equals(m_proofOfReencryption, hd.m_proofOfReencryption);
    }

    @Override
    public int hashCode() {
        return Objects.hash(m_request, m_valueRangeProof, m_senderRerandomizedValue, m_receiverValue,
                m_proofOfRerandomize, m_proofOfReencryption);
    }
}
