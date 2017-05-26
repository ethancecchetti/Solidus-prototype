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

import java.math.BigInteger;

import org.bouncycastle.crypto.ec.ECPair;
import org.bouncycastle.math.ec.ECPoint;

/**
 * This class provides a skeletal implementation of the
 * {@link solidus.util.Encryptor Encryptor} interface based on the
 * {@link #encryptZero encryptZero} method to provide El Gamal encryptions of
 * zero. All other methods are implemented in terms of that one or static
 * values.
 *
 * An extending class can compute these zero encryptions in a variety of ways
 * with varying levels of efficiency.
 *
 * This implementation also allows for {@link org.bouncycastle.math.ec.ECPoint
 * ECPoint}s to be normalized (for faster serialization) as a configuration
 * option at construction time.
 *
 * @see solidus.util.Encryptor
 * @author ethan@cs.cornell.edu
 */
public abstract class AbstractEncryptor implements Encryptor {
    protected final EncryptionParams m_params;
    protected final ECPoint m_publicKey;
    protected final boolean m_normalize;

    public AbstractEncryptor(EncryptionParams params, ECPoint publicKey, boolean normalize) {
        m_params = params;
        m_publicKey = publicKey;
        m_normalize = normalize;
    }

    /**
     * Returns the public key used for encryption by this Encryptor.
     *
     * @see solidus.util.Encryptor#getPublicKey
     */
    @Override
    public ECPoint getPublicKey() {
        return m_publicKey;
    }

    /**
     * This protected method provides a utility that implementing classes can
     * use as a means to generate encryptions of zero. It does not specify how
     * to store them or when to call it, but it is thread-safe and would itself
     * be a valid implementation of {@link #encryptZero() encryptZero}.
     *
     * @return an encryption of zero.
     */
    protected ECPair generateZeroEncryption() {
        BigInteger r = m_params.getRandomIndex();
        if (m_normalize) {
            return new ECPair(m_publicKey.multiply(r).normalize(), m_params.getGenerator().multiply(r).normalize());
        } else {
            return new ECPair(m_publicKey.multiply(r), m_params.getGenerator().multiply(r));
        }
    }

    /**
     * This method defines how to generate encryptions of zero. It is the basic
     * building block of the entire encryption scheme. This may do significant
     * computational work when called or be reading from values computed in the
     * background.
     *
     * Testing classes may implement this method in a highly insecure but very
     * fast way (e.g., always return (0, 0) without performing computation).
     *
     * @see solidus.util.Encryptor#encryptZero
     */
    @Override
    abstract public ECPair encryptZero();

    /**
     * Encrypts the given elliptic curve point as an El Gamal ciphertext.
     *
     * @param point The elliptic curve point to encrypt.
     * @return an El Gamal encryption of {@code point}.
     * @see solidus.util.Encryptor#encryptPoint(ECPoint)
     */
    @Override
    public ECPair encryptPoint(ECPoint point) {
        ECPair zeroEnc = encryptZero();
        if (m_normalize) {
            return new ECPair(point.add(zeroEnc.getX()).normalize(), zeroEnc.getY().normalize());
        } else {
            return new ECPair(point.add(zeroEnc.getX()), zeroEnc.getY());
        }
    }

    /**
     * Multiplies the generator by {@code v} and encrypts the resulting point.
     * Note that this operation is not fully reversible.
     *
     * @param v The discrete log of the point to be encrypted.
     * @return an El Gamal encryption of {@code v * G}.
     * @see solidus.util.Encryptor#encryptValue(BigInteger)
     */
    @Override
    public ECPair encryptValue(BigInteger v) {
        if (BigInteger.ZERO.equals(v)) {
            return encryptZero();
        } else {
            return encryptPoint(m_params.getGenerator().multiply(v));
        }
    }

    /**
     * Encrypts the given balance by multiplying the group generator by it and
     * then encrypting the resulting point. The given balance must be small
     * enough that the system can compute the discrete log (completely reversing
     * this operation) using its lookup table.
     *
     * @param balance The balance to be encrypted.
     * @return an El Gamal encryption of {@code balance * G}.
     * @throws IllegalArgumentException if {@code balance} is too large
     *             (positive or negative) to decrypt with a lookup table.
     * @see solidus.util.Encryptor#encryptBalance(long)
     */
    @Override
    public ECPair encryptBalance(long balance) {
        if (!m_params.isDecryptable(balance))
            throw new IllegalArgumentException("Balance exceeds maximum balance: " + balance);
        return encryptValue(BigInteger.valueOf(balance));
    }

    /**
     * Re-randomizes the given encryption assuming it is encrypted with the same
     * public key as this Encryptor object. If not, an arbitrary (and
     * un-decryptable) value will be returned. To perform this reencryption, we
     * just homomorphically combine with a trivial encryption to allow for
     * efficient precomutation.
     *
     * @param encryption an existing El Gamal encryption of any value under the
     *            same public key used by this Encryptor.
     * @return a re-randomized encryption of the same value.
     * @see solidus.util.Encryptor#reencrypt(ECPair)
     */
    @Override
    public ECPair reencrypt(ECPair encryption) {
        ECPair zeroEnc = encryptZero();
        if (m_normalize) {
            return new ECPair(encryption.getX().add(zeroEnc.getX()).normalize(),
                    encryption.getY().add(zeroEnc.getY()).normalize());
        } else {
            return new ECPair(encryption.getX().add(zeroEnc.getX()), encryption.getY().add(zeroEnc.getY()));
        }
    }
}
