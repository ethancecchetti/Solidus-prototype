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

package solidus.zkproofs;

import org.bouncycastle.math.ec.ECPoint;

import solidus.io.SerialWriter;

/**
 * This class represents a signature with a public verification key of a single
 * ECPoint. The message is represented as any number of byte arrays which are
 * concatenated together.
 */
public interface Signature extends SerialWriter {
    public boolean verify(ECPoint verificationKey, byte[]... messageParts);

    default public boolean verify(ECPoint verificationKey, SerialWriter firstMessagePart,
            SerialWriter... messageParts) {
        byte[][] byteMessageParts = new byte[messageParts.length + 1][];
        byteMessageParts[0] = firstMessagePart.toByteArray();
        for (int i = 0; i < messageParts.length; i++) {
            byteMessageParts[i + 1] = messageParts[i].toByteArray();
        }
        return verify(verificationKey, byteMessageParts);
    }
}
