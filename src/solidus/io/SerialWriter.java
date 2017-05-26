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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

/**
 * This interface is to be used by all non-primitive values that must be
 * serialized within the Solidus system.
 *
 * Java's default serialization results in very large representations and is not
 * portable between implementations of the same protocol. Anything implementing
 * this interface should serialize to a consistent and (relatively) compressed
 * stream.
 *
 * Any class implementing this interface is also expected to implement a public
 * static {@code serialReadIn(InputStream,EncryptionParams)} method to
 * deserialize.
 *
 * @author ethan@cs.cornell.edu
 */
public interface SerialWriter {
    /**
     * Serializes this object to the given OutputStream.
     *
     * @param outStream the output stream to write serialized output to.
     * @param compressPoints whether to write compressed representations of
     *            elliptic curve points.
     * @throws IOException if something goes wrong writing to {@code outStream}.
     *
     * @see #toByteArray
     * @see #toByteArray(boolean)
     */
    public void serialWriteOut(OutputStream outStream, boolean compressPoints) throws IOException;

    /**
     * Serializes this object directly to a byte array using the encoding
     * specified in {@link #serialWriteOut} and compressing elliptic curve
     * points.
     *
     * @return a serialized representation of this object as a byte array.
     *
     * @see #toByteArray(boolean)
     * @see #serialWriteOut(OutputStream, boolean)
     */
    default public byte[] toByteArray() {
        return toByteArray(true);
    }

    /**
     * Serializes this object directly to a byte array using the encoding
     * specified in {@link #serialWriteOut}.
     *
     * @param compressPoints whether to compress the representation of elliptic
     *            curve points.
     * @return a serialized representation of this object as a byte array.
     *
     * @see #toByteArray
     * @see #serialWriteOut(OutputStream, boolean)
     */
    default public byte[] toByteArray(boolean compressPoints) {
        try {
            ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
            serialWriteOut(byteStream, compressPoints);
            return byteStream.toByteArray();
        } catch (IOException e) {
            // This should never happen since there's no real IO here.
            throw new RuntimeException(e);
        }
    }
}
