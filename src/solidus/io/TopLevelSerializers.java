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

package solidus.io;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import solidus.trans.Transaction;
import solidus.trans.TransactionHeader;
import solidus.util.EncryptionParams;

/**
 * This is a static utility class for performing top-level serialization and
 * deserialization. These methods are designed to serialize values that will be
 * sent directly over the network and for deserializing values that come from
 * the network. They are application-level data blobs, so they do not include
 * source or destination information, but they do include application-level
 * headers.
 *
 * @author ethan@cs.cornell.edu
 */
public class TopLevelSerializers {
    public static byte[] serializeTransactionHeader(EncryptionParams params, TransactionHeader header) {
        return _topLevelSerialize(params, header);
    }

    public static TransactionHeader deserializeTransactionHeader(EncryptionParams params, byte[] data) {
        return _topLevelDeserialize(params, data, TransactionHeader::serialReadIn);
    }

    public static byte[] serializeTxSenderInfo(EncryptionParams params, Transaction.SenderInfo senderInfo) {
        return _topLevelSerialize(params, senderInfo);
    }

    public static Transaction.SenderInfo deserializeTxSenderInfo(EncryptionParams params, byte[] data) {
        return _topLevelDeserialize(params, data, Transaction.SenderInfo::serialReadIn);
    }

    public static byte[] serializeTransaction(EncryptionParams params, Transaction transaction) {
        return _topLevelSerialize(params, transaction);
    }

    public static Transaction deserializeTransaction(EncryptionParams params, byte[] data) {
        return _topLevelDeserialize(params, data, Transaction::serialReadIn);
    }

    private static byte[] _topLevelSerialize(EncryptionParams params, SerialWriter serialWriter) {
        try {
            ByteArrayOutputStream outStream = new ByteArrayOutputStream();
            SerialHelpers.writeHeaders(outStream, params);
            serialWriter.serialWriteOut(outStream, params.compressSerializedPoints());
            return outStream.toByteArray();
        } catch (IOException e) {
            // Not much to do here right now.
            throw new RuntimeException(e);
        }
    }

    private static <T> T _topLevelDeserialize(EncryptionParams params, byte[] data, SerialReader<T> reader) {
        try {
            ByteArrayInputStream inStream = new ByteArrayInputStream(data);
            if (!SerialHelpers.verifyHeaders(inStream, params)) {
                throw new IllegalArgumentException("Serialization was for the wrong parameter set.");
            }

            return reader.serialReadIn(inStream, params);
        } catch (IOException e) {
            // Not much to do here right now.
            throw new RuntimeException(e);
        }
    }

    // This is a static utility class that should never be instantiated.
    private TopLevelSerializers() {}
}
