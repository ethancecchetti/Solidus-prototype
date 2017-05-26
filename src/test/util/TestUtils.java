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

package test.util;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import org.junit.Assert;

import solidus.io.SerialReader;
import solidus.io.SerialWriter;
import solidus.util.EncryptionParams;

/**
 * This is a static utility class used for testing purposes.
 *
 * @author ethan@cs.cornell.edu
 */
public class TestUtils {
    public static long RANDOM_SEED = 0xe17d22de01d1a533L;

    /**
     * This method uses JUnit assertions to test the serialization mechanism of
     * a {@code SerialWriter}. It ensures that serializing and deserializing
     * results in a value that is equal (according to {@code .equals()}) and
     * further checks that the resulting value serializes to an identical byte
     * array as the original. This is checked both for compressing points and
     * not.
     *
     * @see solidus.io.SerialWriter
     */
    public static void testSerialization(SerialWriter val, SerialReader<? extends SerialWriter> deserialize,
            EncryptionParams params) {
        try {
            _checkSerialization(val, deserialize, params, true);
            _checkSerialization(val, deserialize, params, false);
        } catch (IOException e) {
            Assert.fail(e.toString());
        }
    }

    /**
     * Helper method to check serialization on either compressed or
     * non-compressed points, but not both.
     */
    private static void _checkSerialization(SerialWriter val, SerialReader<? extends SerialWriter> deserialize,
            EncryptionParams params, boolean compressPoints) throws IOException {
        byte[] serialized = val.toByteArray(compressPoints);
        SerialWriter deserialized = deserialize.serialReadIn(new ByteArrayInputStream(serialized), params);

        Assert.assertEquals(val, deserialized);
        Assert.assertArrayEquals(serialized, deserialized.toByteArray(compressPoints));
    }

    private TestUtils() {}
}
