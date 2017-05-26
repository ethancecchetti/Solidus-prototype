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
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;

import org.bouncycastle.crypto.ec.ECPair;
import org.bouncycastle.math.ec.ECPoint;

import com.google.common.base.Charsets;

import solidus.util.EncryptionParams;

/**
 * This class provides several static utility methods for reading and writing
 * specific types of values from IO streams in a byte-packed manner. Each reader
 * assumes that the correct type of value is being read with only minimal sanity
 * checking. Writers write in the format expected by the associated reader.
 *
 * @author ethan@cs.cornell.edu
 */
public class SerialHelpers {
    /**
     * Reads a {@code BigInteger} from the given {@code InputStream}. The
     * {@code BigInteger} is expected to be formatted as a four-byte integer
     * followed by a byte array compatible with <a target="_blank" href=
     * "https://docs.oracle.com/javase/8/docs/api/java/math/BigInteger.html#BigInteger-byte:A-">
     * BigInteger's byte[] constructor</a>, where the integer specifies the
     * length of the byte array.
     *
     * @param stream the {@code InputStream} from which to read.
     * @return the {@code BigInteger} read from the stream.
     * @throws EOFException if there are not enough bytes in {@code stream}.
     * @throws IOException if there is a problem reading from {@code stream}.
     * @see java.math.BigInteger
     */
    public static BigInteger readBigInteger(InputStream stream) throws IOException {
        int length = stream.read();
        if (length < 0)
            throw new EOFException();
        else if (length == 0) throw new IllegalStateException("Tried to read BigInteger of length 0");

        byte[] buffer = new byte[length];
        int bytesRead = stream.read(buffer);
        if (bytesRead < length) throw new EOFException();

        return new BigInteger(buffer);
    }

    /**
     * Reads a {@code boolean} from the given {@code InputStream}. The
     * {@code boolean} is expected to be a single byte with value 0 or 1.
     *
     * @param stream the {@code InputStream} from which to read.
     * @return the {@code boolean} read from the stream.
     * @throws IllegalStateException if the next byte is not 0 or 1.
     * @throws EOFException if there are not enough bytes in {@code stream}.
     * @throws IOException if there is a problem reading from {@code stream}.
     */
    public static boolean readBoolean(InputStream stream) throws IOException {
        int val = stream.read();
        if (val < 0)
            throw new EOFException();
        else if (val > 1) throw new IllegalStateException("Expected 0 or 1, received: " + val);
        return val == 1;
    }

    /**
     * Reads an {@code ECPair} from the given {@code InputStream}. The
     * {@code ECPair} is expected to be formatted as two {@code ECPoint}'s
     * serialized in sequence in the format written by
     * {@link #writeECPoint(OutputStream,ECPoint,boolean) writeECPoint}.
     *
     * @param stream the {@code InputStream} from which to read.
     * @param params the {@code EncryptionParams} used to decode the point.
     * @return the read {@code ECPair}
     * @throws EOFException if there are not enough bytes in {@code stream}.
     * @throws IOException if there is a problem reading from {@code stream}.
     */
    public static ECPair readECPair(InputStream stream, EncryptionParams params) throws IOException {
        ECPoint xPoint = readECPoint(stream, params);
        ECPoint yPoint = readECPoint(stream, params);
        return new ECPair(xPoint, yPoint);
    }

    /**
     * Reads an {@code ECPoint} from the given {@code InputStream}. The
     * {@code ECPoint} is expected to be formatted as an integer followed by a
     * byte array where the integer specifies the length of the array. The point
     * is decoded using {@link solidus.util.EncryptionParams#decodePoint(byte[])
     * params.decodePoint}.
     *
     * @param stream the {@code InputStream} from which to read.
     * @param params the {@code EncryptionParams} used to decode the point.
     * @return the read {@code ECPoint}
     * @throws EOFException if there are not enough bytes in {@code stream}.
     * @throws IOException if there is a problem reading from {@code stream}.
     */
    public static ECPoint readECPoint(InputStream stream, EncryptionParams params) throws IOException {
        int length = stream.read();
        if (length < 0) throw new EOFException();

        byte[] buffer = new byte[length];
        int bytesRead = stream.read(buffer);
        if (bytesRead < length) throw new EOFException();

        return params.decodePoint(buffer);
    }

    /**
     * Reads an {@code int} from the given {@code InputStream}. The {@code int}
     * is expected to be four bytes in big endian.
     *
     * @param stream the {@code InputStream} from which to read.
     * @return the read integer
     * @throws EOFException if there are not enough bytes in {@code stream}.
     * @throws IOException if there is a problem reading from {@code stream}.
     */
    public static int readInt(InputStream stream) throws IOException {
        int value = 0;
        for (int i = 0; i < 4; i++) {
            value <<= 8;
            int unsignedByte = stream.read();
            if (unsignedByte < 0) throw new EOFException();
            value |= unsignedByte;
        }
        return value;
    }

    /**
     * Reads a {@code long} from the given {@code InputStream}. The {@code long}
     * is expected to be four bytes in big endian.
     *
     * @param stream the {@code InputStream} from which to read.
     * @return the read {@code long} value
     * @throws EOFException if there are not enough bytes in {@code stream}.
     * @throws IOException if there is a problem reading from {@code stream}.
     */
    public static long readLong(InputStream stream) throws IOException {
        long value = 0;
        for (int i = 0; i < 8; i++) {
            value <<= 8;
            int unsignedByte = stream.read();
            if (unsignedByte < 0) throw new EOFException();
            value |= unsignedByte;
        }
        return value;
    }

    /**
     * Reads a UTF-8 encoded, null-terminated {@code String} from the given
     * {@code InputStream}.
     *
     * @param stream the {@code InputStream} from which to read.
     * @return the read {@code String} value
     * @throws EOFException if {@code stream} ends before a 0 byte.
     * @throws IOException if there is a problem reading from {@code stream}.
     */
    public static String readString(InputStream stream) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        int nextByte = stream.read();
        while (nextByte > 0) {
            buffer.write(nextByte);
            nextByte = stream.read();
        }
        if (nextByte < 0) throw new EOFException();
        return buffer.toString(Charsets.UTF_8.name());
    }

    /**
     * Reads a set of headers written by
     * {@link #writeHeaders(OutputStream, EncryptionParams) writeHeaders} and
     * checks if they match up with the parameters in {@code params}.
     *
     * @param stream the {@code InputStream} from which to read.
     * @param params the current {@code EncryptionParams} to check agains.
     * @return whether the headers of {@code stream} match the specified
     *         configuration
     * @throws EOFException if {@code stream} ends before headers are complete.
     * @throws IOException if there is a problem reading from {@code stream}.
     */
    public static boolean verifyHeaders(InputStream stream, EncryptionParams params) throws IOException {
        int versionId = readInt(stream);
        String curveName = readString(stream);
        String hashAlgorithm = readString(stream);
        long transactionTimeout = readLong(stream);

        return versionId == EncryptionParams.VERSION_ID && curveName.equals(params.getCurveName())
                && hashAlgorithm.equals(params.getHashAlgorithm())
                && transactionTimeout == params.getTransactionTimeoutMillis();
    }

    /**
     * Writes a {@code BigInteger} to the given {@code OutputStream}. The
     * {@code BigInteger} is encoded as a four-byte integer {@code n} followed
     * by {@code n} bytes where the bytes are compatible with {@code BigInteger}
     * 's <a target="_blank" href=
     * "https://docs.oracle.com/javase/8/docs/api/java/math/BigInteger.html#BigInteger-byte:A-">
     * byte[]</a> constructor.
     *
     * @param stream the {@code OutputStream} to write to.
     * @param value the value to write out.
     * @throws IOException if there is a problem writing to {@code stream}.
     * @see java.math.BigInteger
     */
    public static void writeBigInteger(OutputStream stream, BigInteger value) throws IOException {
        byte[] array = value.toByteArray();
        if (array.length > 0xff)
            throw new IllegalArgumentException("Cannot write BigInteger with more than 255 bytes.");
        stream.write(array.length);
        stream.write(array);
    }

    /**
     * Writes a {@code boolean} to the given {@code OutputStream}. The
     * {@code boolean} is encoded as a single byte with value 0 or 1.
     *
     * @param stream the {@code OutputStream} to write to.
     * @param value the value to write out.
     * @throws IOException if there is a problem writing to {@code stream}.
     */
    public static void writeBoolean(OutputStream stream, boolean value) throws IOException {
        stream.write(value ? 1 : 0);
    }

    /**
     * Writes an {@code ECPair} to the given {@code OutputStream}. The
     * {@code ECPair} is encoded as a two consecutive {@code ECPoint}s as
     * written by {@link #writeECPoint(OutputStream, ECPoint, boolean)
     * writeECPoint}. Both points are compressed or not, as specified by
     * {@code compressed}.
     *
     * @param stream the {@code OutputStream} to write to.
     * @param pair the pair of elliptic curve points to write out.
     * @param compressed whether or not use a compressed point encoding.
     * @throws IOException if there is a problem writing to {@code stream}.
     */
    public static void writeECPair(OutputStream stream, ECPair pair, boolean compressed) throws IOException {
        writeECPoint(stream, pair.getX(), compressed);
        writeECPoint(stream, pair.getY(), compressed);
    }

    /**
     * Write an {@code ECPoint} to the given {@code OutputStream}. The
     * {@code ECPoint} is encoded as a four-byte integer in big endian
     * specifying the length of the encoding, followed the encoding as a
     * sequence of bytes as generated by
     * {@link org.bouncycastle.math.ec.ECPoint#getEncoded(boolean)}.
     *
     * @param stream the {@code InputStream} from which to read.
     * @param point the elliptic curve point to write out.
     * @param compressed whether or not to use a compressed encoding.
     * @throws IOException if there is a problem reading from {@code stream}.
     * @see org.bouncycastle.math.ec.ECPoint#getEncoded(boolean)
     */
    public static void writeECPoint(OutputStream stream, ECPoint point, boolean compressed) throws IOException {
        byte[] encoding = point.getEncoded(compressed);
        if (encoding.length > 0xff)
            throw new IllegalArgumentException("Cannot write points whose encoding exceeds 255 bytes.");
        stream.write(encoding.length);
        stream.write(encoding);
    }

    /**
     * Writes a set of top-level headers to {@code stream} based on the values
     * set in {@code params}.
     *
     * @param stream the {@code OutputStream} to write to.
     * @param params the {@code EncryptionParams} currently in use.
     * @throws IOException if there is a problem writing to {@code stream}.
     */
    public static void writeHeaders(OutputStream stream, EncryptionParams params) throws IOException {
        writeInt(stream, EncryptionParams.VERSION_ID);
        writeString(stream, params.getCurveName());
        writeString(stream, params.getHashAlgorithm());
        writeLong(stream, params.getTransactionTimeoutMillis());
    }

    /**
     * Writes an {@code int} to the given {@code OutputStream}. The {@code int}
     * is encoded as four bytes in big endian.
     *
     * @param stream the {@code OutputStream} to write to.
     * @param value the value to write out.
     * @throws IOException if there is a problem writing to {@code stream}.
     */
    public static void writeInt(OutputStream stream, int value) throws IOException {
        stream.write(new byte[] { (byte) (value >>> 24), (byte) (value >>> 16), (byte) (value >>> 8), (byte) (value) });
    }

    /**
     * Writes a {@code long} to the given {@code OutputStream}. The {@code long}
     * is encoded as eight bytes in big endian.
     *
     * @param stream the {@code OutputStream} to write to.
     * @param value the value to write out.
     * @throws IOException if there is a problem writing to {@code stream}.
     */
    public static void writeLong(OutputStream stream, long value) throws IOException {
        stream.write(
                new byte[] { (byte) (value >>> 56), (byte) (value >>> 48), (byte) (value >>> 40), (byte) (value >>> 32),
                        (byte) (value >>> 24), (byte) (value >>> 16), (byte) (value >>> 8), (byte) (value) });
    }

    /**
     * Writes a {@code String} to the given {@code OutputStream} encoded in
     * UTF-8 and terminated with a single 0 byte.
     *
     * @param stream the {@code OutputStream} to write to.
     * @param value the string to write out.
     * @throws IOException if there is a problem writing to {@code stream}.
     */
    public static void writeString(OutputStream stream, String value) throws IOException {
        stream.write(value.getBytes(Charsets.UTF_8));
        stream.write(0);
    }

    // This is a static utility class that should never be instantiated.
    private SerialHelpers() {}
}
