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

package solidus.util;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

import org.bouncycastle.crypto.ec.ECPair;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;

/**
 * This class provides the main source of dependency induction for the Solidus
 * system. It specifies the source of randomness, the elliptic curve to use for
 * encryption, and the hash function. It also specifies a variety of other
 * configuration options including maximum balances and transaction timeouts.
 * Every core piece of functionality requires an instance of EncryptionParams.
 *
 * This class (not including the builder) is thread-safe. All (non-builder)
 * operations on mutable state are internally synchronized.
 *
 * @author ethan@cs.cornell.edu
 */
public class EncryptionParams {
    public static final int VERSION_ID = 0x00000001;

    private static final List<Byte> DEFAULT_HASH_INDEX = ImmutableList.of((byte) 0);

    /**
     * (THIS IS FOR TESTING ONLY) Constructs a new {@code EncryptionParams}
     * object with the specified randomness, curve, and digest and all other
     * values set to default testing mode.
     *
     * @param rand the source of randomness
     * @param curveSpec the elliptic curve
     * @param digestSupplier a constructor for a hash algorithm
     * @return a fresh {@code EncryptionParams} object with the specified
     *         configuration.
     */
    public static EncryptionParams newTestParams(Random rand, ECNamedCurveParameterSpec curveSpec,
            Supplier<MessageDigest> digestSupplier) {
        return new Builder(rand, curveSpec, digestSupplier).forTesting().build();
    }

    private final Random m_random;
    private final ECNamedCurveParameterSpec m_curveSpec;
    private final ECPoint m_infinity;
    private final Supplier<MessageDigest> m_digestSupplier;

    private final long m_maxDiscreteLog;
    private final int m_maxDiscreteLogBits;
    private final int m_discreteLogTableGap;

    private final boolean m_fastTestEncryptor;
    private final int m_encryptorThreads;
    private final int m_encryptorQueueSize;
    private final Map<ECPoint, Path> m_storedEncryptionPathMap;

    private final boolean m_normalizePoints;
    private final boolean m_compressSerializedPoints;
    private final boolean m_blindDecryption;

    private final long m_transactionTimeoutMs;

    private final Map<ECPoint, Long> m_discreteLogMap;

    private final Map<ECPoint, Encryptor> m_encryptorCache;

    private EncryptionParams(Builder builder) {
        m_random = builder.m_random;
        m_curveSpec = builder.m_curveSpec;
        m_infinity = m_curveSpec.getCurve().getInfinity().normalize();
        m_digestSupplier = builder.m_digestSupplier;

        m_maxDiscreteLog = builder.m_maxDiscreteLog;
        if (builder.m_maxDiscreteLogBits == -1) {
            m_maxDiscreteLogBits = Long.SIZE - Long.numberOfLeadingZeros(m_maxDiscreteLog);
        } else {
            m_maxDiscreteLogBits = builder.m_maxDiscreteLogBits;
        }
        m_discreteLogTableGap = builder.m_discreteLogTableGap;

        m_fastTestEncryptor = builder.m_fastTestEncryptor;
        m_encryptorThreads = builder.m_encryptorThreads;
        m_encryptorQueueSize = builder.m_encryptorQueueSize;
        m_storedEncryptionPathMap = ImmutableMap.copyOf(builder.m_storedEncryptionPathMap);

        m_normalizePoints = builder.m_normalizePoints;
        m_compressSerializedPoints = builder.m_compressSerializedPoints;
        m_blindDecryption = builder.m_blindDecryption;

        m_transactionTimeoutMs = builder.m_transactionTimeoutMs;

        m_discreteLogMap = _buildDiscreteLogMap();

        m_encryptorCache = new HashMap<>();
    }

    private Map<ECPoint, Long> _buildDiscreteLogMap() {
        ImmutableMap.Builder<ECPoint, Long> discreteLogMapBuilder = ImmutableMap.builder();
        ECPoint genMultiple = getGenerator().multiply(BigInteger.valueOf(m_discreteLogTableGap));
        ECPoint currentPoint = getInfinity();
        for (long i = 0; i <= m_maxDiscreteLog; i += m_discreteLogTableGap, currentPoint = currentPoint.add(genMultiple)
                .normalize()) {
            discreteLogMapBuilder.put(currentPoint, i);
        }
        // We need to ensure that the max balance is in the table because it
        // means we don't have to worry about directional shifts on decryption.
        if (m_maxDiscreteLog % m_discreteLogTableGap != 0) {
            discreteLogMapBuilder.put(getGenerator().multiply(BigInteger.valueOf(m_maxDiscreteLog)).normalize(),
                    m_maxDiscreteLog);
        }

        return discreteLogMapBuilder.build();
    }

    /**
     * Returns the common name of the elliptic curve used for encryption.
     *
     * @return the common name of the elliptic curve used for encryption.
     */
    public String getCurveName() {
        return m_curveSpec.getName();
    }

    /**
     * Returns the name of the hash algorithm being used.
     *
     * @return the name of the hash algorithm being used.
     */
    public String getHashAlgorithm() {
        return m_digestSupplier.get().getAlgorithm();
    }

    /**
     * Returns whether or not the specified balance is possible to decrypt using
     * the existing lookup table.
     *
     * @param balance a balance value that may or may not be decryptable.
     * @return whether or not the {@code balance} is possible to decrypt using
     *         the existing lookup table.
     */
    public boolean isDecryptable(long balance) {
        return m_maxDiscreteLog < 0 || Math.abs(balance) <= m_maxDiscreteLog;
    }

    /**
     * Returns the maximum decryptable balance (largest discrete log in the
     * lookup table).
     *
     * @return the maximum decryptable balance (largest discrete log in the
     *         lookup table).
     */
    public long getMaxDiscreteLog() {
        return m_maxDiscreteLog;
    }

    /**
     * Returns the maximum number of bits possible in a decryptable balance, to
     * be used for determining the number of bits used in range proofs.
     *
     * @return the maximum number of bits possible in a decryptable balance, to
     *         be used for determining the number of bits used in range proofs.
     */
    public int getMaxDiscreteLogBits() {
        return m_maxDiscreteLogBits;
    }

    /**
     * Returns the size of the elliptic curve group used for encryption.
     *
     * @return the size of the elliptic curve group used for encryption.
     */
    public BigInteger getGroupSize() {
        return m_curveSpec.getN();
    }

    /**
     * Returns "infinity", the identity point of the elliptic curve.
     *
     * @return "infinity", the identity point of the elliptic curve.
     */
    public ECPoint getInfinity() {
        return m_infinity;
    }

    /**
     * Returns the generator of the elliptic curve group used for encryption.
     *
     * @return the generator of the elliptic curve group used for encryption.
     */
    public ECPoint getGenerator() {
        return m_curveSpec.getG();
    }

    /**
     * Returns whether or not elliptic curve points should be serialized in a
     * compressed representation.
     *
     * @return whether or not elliptic curve points should be serialized in a
     *         compressed representation.
     */
    public boolean compressSerializedPoints() {
        return m_compressSerializedPoints;
    }

    /**
     * Returns the transaction timeout in milliseconds to determine how far back
     * the system must search to ensure unique transaction IDs.
     *
     * NOTE: This is currently unused as transaction timeouts have not yet been
     * implemented.
     *
     * @return the transaction timeout in milliseconds to determine how far back
     *         the system must search to ensure unique transaction IDs.
     */
    public long getTransactionTimeoutMillis() {
        return m_transactionTimeoutMs;
    }

    /**
     * Returns the {@code ECPoint} obtained by decoding the specified buffer
     * with the current curve's {@code decodePoint} method.
     *
     * @param buffer the byte array to decode.
     * @return the {@code ECPoint} obtained by decoding the specified buffer
     *         with the current curve's {@code decodePoint} method.
     * @see org.bouncycastle.math.ec.ECCurve#decodePoint(byte[])
     */
    public ECPoint decodePoint(byte[] buffer) {
        return m_curveSpec.getCurve().decodePoint(buffer);
    }

    /**
     * Returns the source of randomness used within this Solidus instance.
     *
     * @return the source of randomness used within this Solidus instance.
     */
    public Random getRandomSource() {
        return m_random;
    }

    /**
     * Returns a random integer in the range (0, N) where N is the size of the
     * elliptic curve group (as returned by {@link #getGroupSize() getGroupSize}
     * ).
     *
     * @return a random integer in the range (0, N) where N is the size of the
     *         elliptic curve group (as returned by {@link #getGroupSize()
     *         getGroupSize}).
     */
    public BigInteger getRandomIndex() {
        BigInteger r;
        r = new BigInteger(getGroupSize().bitLength(), m_random);
        while (r.compareTo(getGroupSize()) >= 0 || r.compareTo(BigInteger.ONE) < 0) {
            r = new BigInteger(getGroupSize().bitLength(), m_random);
        }
        return r;
    }

    /**
     * Hashes any number of {@code ECPoint}s into a an integer between 0 and the
     * group size using hashing algorithm specified on construction. This method
     * is guaranteed to return the same result if given the same inputs multiple
     * times. The same hash function must be used by every node in a Solidus
     * system for proofs to verify.
     *
     * Implementation note: This method uses the hash function supplied at
     * construction and provides with a 0 byte followed by the compressed
     * encoding of each point in the order provided.
     *
     * @param points any number of {@code ECPoint} objects to encode and hash.
     * @return the combined hash of all specified points.
     */
    public BigInteger hash(ECPoint... points) {
        return hashEachIndexWithAllPoints(DEFAULT_HASH_INDEX, points).get(0);
    }

    /**
     * Flatens the two-dimentional byte array of data, encodes each of the
     * provided points, and hashes the result into a {@code BigInteger} between
     * 0 and the size of the elliptic curve group. This method is designed to be
     * used for digital signatures which require hashing the message to be
     * signed with some cryptographic information.
     *
     * This method flattens the data array by interpreting the inner arrays as
     * sub-arrays (so the first inner array is the first piece of the flattened
     * value). The data is provided to the hash algorithm prior to compressed
     * encodings of each point specified in the order given.
     *
     * @param data a two dimentional array of {@code bytes} to flatten and
     *            include in the point hash.
     * @param points any number of elliptic curve points to include in the hash.
     * @return the combined hash of all data and points provided.
     */
    public BigInteger hashDataAndPoints(byte[][] data, ECPoint... points) {
        MessageDigest digest = m_digestSupplier.get();
        for (byte[] d : data)
            digest.update(d);
        for (ECPoint point : points)
            digest.update(point.getEncoded(true));
        return new BigInteger(digest.digest()).mod(getGroupSize());
    }

    /**
     * Takes an array of byte indices and any number of {@code ECPoint}s and
     * produces a hash for each index including that indices and all points in
     * the hash arguments using the hash algorithm specified on construction.
     * Each output is a {@code BigInteger} between 0 and the group size.
     *
     * This method is useful when we need to generate a sequence of challenges.
     *
     * @param indices a list of bytes to prepend to the encoded points with each
     *            hash.
     * @param points any number of points to encode and hash in the order
     *            provided
     * @return a list of numbers between 0 and the group size, one for each byte
     *         in {@code indices}.
     */
    public List<BigInteger> hashEachIndexWithAllPoints(List<Byte> indices, ECPoint... points) {
        // Compressed encodings are marginally faster.
        byte[][] encodings = new byte[points.length][];
        for (int i = 0; i < points.length; i++)
            encodings[i] = points[i].getEncoded(true);

        MessageDigest digest = m_digestSupplier.get();
        ImmutableList.Builder<BigInteger> hashesBuilder = new ImmutableList.Builder<>();
        for (byte index : indices) {
            digest.update(index);
            for (byte[] d : encodings)
                digest.update(d);
            hashesBuilder.add(new BigInteger(digest.digest()).mod(getGroupSize()));
        }
        return hashesBuilder.build();
    }

    /**
     * Returns an El Gamal Encryptor corresponding to the given public key. This
     * function will cache {@code Encryptor} objects for a given public key and
     * return the same object on future invocations with the same key. If there
     * is a file specified to pull precomputed encryptions for the give key, the
     * encryptor will use encryptions from that file first before beginning to
     * compute them online.
     *
     * @param publicKey the El Gamal public key to get an
     *            {@link solidus.util.Encryptor Encryptor} for.
     * @return an {@link solidus.util.Encryptor Encryptor} object associated
     *         with the given public key.
     */
    public Encryptor getEncryptor(ECPoint publicKey) {
        synchronized (m_encryptorCache) {
            Encryptor encryptor = m_encryptorCache.get(publicKey);
            if (encryptor == null) {
                Path storedEncryptionsPath = m_storedEncryptionPathMap.get(publicKey);
                if (m_fastTestEncryptor) {
                    final BigInteger r = getRandomIndex();
                    final ECPoint pubKeyPoint = publicKey.multiply(r).normalize();
                    final ECPoint genPoint = getGenerator().multiply(r).normalize();
                    encryptor = new AbstractEncryptor(this, publicKey, m_normalizePoints) {
                        @Override
                        public ECPair encryptZero() {
                            return new ECPair(pubKeyPoint, genPoint);
                        }
                    };
                } else if (storedEncryptionsPath != null) {
                    try {
                        encryptor = new FromFileEncryptor(this, publicKey, storedEncryptionsPath, m_normalizePoints,
                                m_encryptorThreads, m_encryptorQueueSize);
                    } catch (IOException e) {
                        // This is recoverable by creating an OnlineEncryptor,
                        // but for now, we will blow up because it indicates
                        // something is broken and we don't have good logging
                        // infrastructure.
                        throw new IllegalStateException("Something went wrong reading the encryptions backing file.",
                                e);
                    }
                } else {
                    encryptor = new OnlineEncryptor(this, publicKey, m_normalizePoints, m_encryptorThreads,
                            m_encryptorQueueSize);
                }
                m_encryptorCache.put(publicKey, encryptor);
            }
            return encryptor;
        }
    }

    /**
     * Constructs an El Gamal {@link solidus.util.Decryptor Decryptor} object
     * with the specified secret key.
     *
     * @param secretKey the secret decryption key to use for decryption.
     * @return an El Gamal Decryptor corresponding to the given secret key.
     */
    public Decryptor getDecryptor(BigInteger secretKey) {
        return new Decryptor(this, secretKey, m_blindDecryption);
    }

    /**
     * This method makes use of a lookup table to attemp to get the discrete log
     * of the given point. It only works if the absolute value of the discrete
     * log is at most the maximum balance specified with this object was
     * constructed.
     *
     * @param point The elliptic curve point to attempt to find the discrete log
     *            of.
     * @return the discrete log of the point relative to {@link #getGenerator()}
     *         .
     * @throws IllegalArgumentException if the discrete log cannot be found.
     */
    public long lookupDiscreteLog(ECPoint point) {
        // This actually decrypts slightly larger negative values
        // since they'll be pushed up to the maximum value. That's fine.
        for (int i = 0; i < m_discreteLogTableGap; i++) {
            Long positiveLookup = m_discreteLogMap.get(point);
            if (positiveLookup != null) {
                return positiveLookup.longValue() - i;
            }
            Long negativeLookup = m_discreteLogMap.get(point.negate());
            if (negativeLookup != null) {
                return (-negativeLookup.longValue()) - i;
            }

            point = point.add(getGenerator());
        }

        throw new IllegalArgumentException("Attempted to lookup decryption that is not in table.");
    }

    /**
     * A builder class to construct an {@code EncryptionParams} object. The
     * builder requires a source of randomness, a curve specification, and a
     * hash algorithm. The builder supports a variety of options, some of which
     * are required when not testing.
     */
    public static class Builder {
        private final Random m_random;
        private final ECNamedCurveParameterSpec m_curveSpec;
        private final Supplier<MessageDigest> m_digestSupplier;

        private final Map<ECPoint, Path> m_storedEncryptionPathMap;

        private boolean m_normalizePoints = false;
        private boolean m_compressSerializedPoints = false;
        private boolean m_blindDecryption = false;

        private long m_maxDiscreteLog = -1;
        private int m_maxDiscreteLogBits = -1;
        private int m_discreteLogTableGap = 1;

        private boolean m_fastTestEncryptor = false;
        private int m_encryptorThreads = 0;
        private int m_encryptorQueueSize = 10000;

        private long m_transactionTimeoutMs = -1;

        private boolean m_forTesting = false;

        private boolean m_isBuilt;

        /**
         * Constructs a new {@code Builder} object. The builder requires three
         * mandatory values that have no defaults: a source of randomness, an
         * elliptic curve, and a hash function (specified as a constructor so we
         * can make multiple copies to avoid concurrency problems).
         *
         * @param rand the source of randomness
         * @param curveSpec the elliptic curve
         * @param digestSupplier a constructor for a hash algorithm
         */
        public Builder(Random rand, ECNamedCurveParameterSpec curveSpec, Supplier<MessageDigest> digestSupplier) {
            m_random = rand;
            m_curveSpec = curveSpec;
            m_digestSupplier = digestSupplier;

            m_storedEncryptionPathMap = new HashMap<>();

            m_isBuilt = false;
        }

        /**
         * Specifies that all encryptions and decryptions should be normalized.
         *
         * @return this {@code Builder} object.
         * @throws IllegalStateException if {@link #build()} has already been
         *             invoked.
         */
        public Builder normalizePoints() {
            if (m_isBuilt) throw new IllegalStateException("Cannot set parameters after building.");
            m_normalizePoints = true;
            return this;
        }

        /**
         * Specifies whether or not serialized points should be compressed.
         *
         * @param compress whether or not to compress elliptic curve points
         * @return this {@code Builder} object.
         * @throws IllegalStateException if {@link #build()} has already been
         *             invoked.
         */
        public Builder setCompressSerializedPoints(boolean compress) {
            if (m_isBuilt) throw new IllegalStateException("Cannot set parameters after building.");
            m_compressSerializedPoints = compress;
            return this;
        }

        /**
         * Specifies that decryptions should be blinded. This reduces efficiency
         * of decryption.
         *
         * @return this {@code Builder} object.
         * @throws IllegalStateException if {@link #build()} has already been
         *             invoked.
         */
        public Builder blindDecryption() {
            if (m_isBuilt) throw new IllegalStateException("Cannot set parameters after building.");
            m_blindDecryption = true;
            return this;
        }

        /**
         * Sets the maximum discrete log in the balance-decryption lookup table.
         * This value must be set unless this EncryptionParams is for testing.
         * (If unset, decrypting balances is impossible.)
         *
         * @param maxLog the maximum discrete log value to include in the lookup
         *            table.
         * @return this {@code Builder} object.
         * @throws IllegalArgumentException if {@code maxLog < 0} or if it
         *             cannot be represented by the currently set maximum
         *             discrete log bits {@link #setMaxDiscreteLogBits(int)}
         * @throws IllegalStateException if {@link #build()} has already been
         *             invoked.
         */
        public Builder setMaxDiscreteLog(long maxLog) {
            if (m_isBuilt) throw new IllegalStateException("Cannot set parameters after building.");
            if (maxLog < 0)
                throw new IllegalArgumentException("Must specify a non-negative maximum value for discrete log table.");
            if (m_maxDiscreteLogBits >= 0 && maxLog > (1 << m_maxDiscreteLogBits) - 1)
                throw new IllegalArgumentException(
                        "Maximum bits specified and was too small to represent the given value.");

            m_maxDiscreteLog = maxLog;
            return this;
        }

        /**
         * Sets the maximum number of bits used in representations of the
         * discrete log. This is used for range proofs of decryptable values. If
         * no value is specified, it defaults to the actual number of bits
         * needed to represent the maximum invertible discrete log.
         *
         * @param maxBits the number of bits to use in range proofs.
         * @return this {@code Builder} object.
         * @throws IllegalArgumentException if {@code maxBits} is too small to
         *             represent the actual max discrete log.
         * @throws IllegalStateException if {@link #build()} has already been
         *             invoked.
         */
        public Builder setMaxDiscreteLogBits(int maxBits) {
            if (m_isBuilt) throw new IllegalStateException("Cannot set parameters after building.");
            if ((1 << maxBits) - 1 < m_maxDiscreteLog) throw new IllegalArgumentException(
                    "Must specify a number of bits that can actually represent the maximum discrete log.");

            m_maxDiscreteLogBits = maxBits;
            return this;
        }

        /**
         * Sets the gap between entries in the discrete log lookup table. Larger
         * values result in lower memory footprint and faster initialization,
         * but slow decryption. This value must be at least 1 or the table will
         * be useless (and may not build properly). Default: 1
         *
         * @param gap sets the number of discrete log values between each saved
         *            value.
         * @return this {@code Builder} object.
         * @throws IllegalArgumentException if {@code gap < 1}
         * @throws IllegalStateException if {@link #build()} has already been
         *             invoked.
         */
        public Builder setLookupTableGap(int gap) {
            if (m_isBuilt) throw new IllegalStateException("Cannot set parameters after building.");
            if (gap < 1) throw new IllegalArgumentException("Discrete log table gap must be positive.");

            m_discreteLogTableGap = gap;
            return this;
        }

        /**
         * (THIS IS FOR TESTING ONLY!) Sets the encryption params to always
         * return a fast test encryptor. This will not actually encrypt the
         * data, and instead will use (0, 0) as its zero encryption.
         *
         * @return this {@code Builder} object.
         * @throws IllegalStateException if {@link #build()} has already been
         *             invoked.
         */
        public Builder useFastTestEncryptor() {
            if (m_isBuilt) throw new IllegalStateException("Cannot set parameters after building.");
            m_fastTestEncryptor = true;
            return this;
        }

        /**
         * Sets the number of background threads used for generating
         * reencryption factors. If this value is 0, all reencryptions are
         * generated upon request. Default: 0
         *
         * @param threads the number of background threads to use for each
         *            {@link solidus.util.Encryptor Encryptor} object. Zero
         *            means all encryptions will be generated when requested.
         * @return this {@code Builder} object.
         * @throws IllegalArgumentException if {@code threads < 0}
         * @throws IllegalStateException if {@link #build()} has already been
         *             invoked.
         */
        public Builder setEncryptorThreads(int threads) {
            if (m_isBuilt) throw new IllegalStateException("Cannot set parameters after building.");
            if (threads < 0)
                throw new IllegalArgumentException("Cannot specify a negative number of background threads");

            m_encryptorThreads = threads;
            return this;
        }

        /**
         * Sets the maximum buffer size for background-generated reencryption
         * factors. This must be a positive value. Default: 10000
         *
         * @param queueSize sets the queue size to be used for encryptions
         *            generated in the background by
         *            {@link solidus.util.Encryptor Encryptor} objects.
         * @return this {@code Builder} object.
         * @throws IllegalArgumentException if {@code queueSize < 1}
         * @throws IllegalStateException if {@link #build()} has already been
         *             invoked.
         */
        public Builder setEncryptorQueueSize(int queueSize) {
            if (m_isBuilt) throw new IllegalStateException("Cannot set parameters after building.");
            if (queueSize < 1) throw new IllegalArgumentException("Encryptor buffer size must be positive");

            m_encryptorQueueSize = queueSize;
            return this;
        }

        /**
         * Provides a file from which to pull precomputed encrypiton
         * randomization factors for the given El Gamal public key. Once all
         * randomization factors in the file are used, more will be computed
         * online using the parameters specified for general online computation.
         *
         * @param key the public encryption key the randomization factors are
         *            associated with.
         * @param filePath the local filesystem file containing precomputed
         *            randomization factors.
         * @return this {@code Builder} object.
         * @throws IllegalArgumentException if {@code filePath} is not a regular
         *             file.
         * @throws IllegalStateException if {@link #build()} has already been
         *             invoked.
         */
        public Builder addKeyToEncryptionFile(ECPoint key, Path filePath) {
            if (m_isBuilt) throw new IllegalStateException("Cannot set parameters after building.");
            if (!Files.isRegularFile(filePath))
                throw new IllegalArgumentException("Stored encryptions must be in regular files.");

            m_storedEncryptionPathMap.put(key, filePath);
            return this;
        }

        /**
         * Sets the timeout for transaction requests to the specified number of
         * seconds. There is no default value and this value must be set except
         * when testing. This value must be set for non-testing configurations.
         *
         * @param duration the duration of the transaction timeout
         * @param unit the {@code TimeUnit} to use for {@code duration}
         * @return this {@code Builder} object.
         */
        public Builder setTransactionTimeout(long duration, TimeUnit unit) {
            if (m_isBuilt) throw new IllegalStateException("Cannot set parameters after building.");
            if (m_transactionTimeoutMs > 0)
                throw new IllegalStateException("Cannot set the transaction timeout twice.");
            if (duration <= 0) throw new IllegalArgumentException("The transaction timeout must be a positive number.");

            m_transactionTimeoutMs = unit.toMillis(duration);
            return this;
        }

        /**
         * (THIS IS FOR TESTING ONLY!) Specifies that this is being used for
         * testing and thus validation should not be performed upon building.
         *
         * @return this {@code Builder} object.
         */
        public Builder forTesting() {
            if (m_isBuilt) throw new IllegalStateException("Cannot set parameters after building.");
            m_forTesting = true;
            return this;
        }

        /**
         * Constructs an {@code EncryptionParams} object from the values set in
         * this {@code Builder}. This method can only be invoked once per
         * object, and once it is invoked no other values can be changed. If the
         * builder was not marked as for testing, then {@code build()} performs
         * validation that required arguments have been set appropriately.
         *
         * @return a new {@link solidus.util.EncryptionParams EncryptionParams}
         *         object with all parameters set as in this {@code Builder}.
         * @throws IllegalStateException if {@code build()} has already been
         *             invoked or if a required argument was not set.
         */
        public EncryptionParams build() {
            if (m_isBuilt) throw new IllegalStateException("Cannot build the same params twice.");
            // If we're for testing, don't bother validating.
            if (!m_forTesting) {
                if (m_maxDiscreteLog < 0)
                    throw new IllegalStateException("Must specify a max discrete log when not for testing.");
                if (m_fastTestEncryptor)
                    throw new IllegalStateException("Cannot use fast test encryptor except while testing.");
                if (m_transactionTimeoutMs <= 0)
                    throw new IllegalStateException("Transaction timeout must be set when not testing.");
            }
            // Except consistency of discrete log because otherwise range proofs
            // can break.
            if (m_maxDiscreteLogBits >= 0
                    && m_maxDiscreteLogBits < Long.SIZE - Long.numberOfLeadingZeros(m_maxDiscreteLog)) {
                throw new IllegalStateException(
                        "Cannot specify max discrete log bits smaller than the discrete log of the max balance.");
            }

            m_isBuilt = true;
            return new EncryptionParams(this);
        }
    }
}
