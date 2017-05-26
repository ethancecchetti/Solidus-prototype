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
 * This class provides a utility to decrypt El Gamal ciphertexts using a given
 * secret key. It is a very simple utility that optionally allows for blinding
 * on decryption for side channel resistance. Blinding reduces performance by
 * approximately a factor of two.
 *
 * @author ethan@cs.cornell.edu
 */
public class Decryptor {
    private final EncryptionParams m_params;
    private final BigInteger m_secretKey;

    private final boolean m_blindDecryption;

    /**
     * Constructs a new {@code Decryptor} object for a specific secret key.
     *
     * @param params the system {@link solidus.util.EncryptionParams} currently
     *            in use.
     * @param secretKey the secret decryption key to use for decryption.
     * @param blindDecryption a {@code boolean} indicating whether or not to
     *            blind decryptions.
     */
    public Decryptor(EncryptionParams params, BigInteger secretKey, boolean blindDecryption) {
        m_params = params;
        m_secretKey = secretKey;
        m_blindDecryption = blindDecryption;

        if (secretKey.compareTo(BigInteger.ONE) <= 0 || secretKey.compareTo(m_params.getGroupSize()) >= 0) {
            throw new IllegalArgumentException("Must specify a secret key between (1, groupSize)");
        }
    }

    /**
     * Decrypts the specified encryption to an elliptic curve point. This is
     * always possible for a valid encryption under the public key associated
     * with the secret key provided when this {@code Decryptor} object was
     * constructed.
     *
     * @param encryption the encryption to decrypt
     * @return the decrypted elliptic curve point
     */
    public ECPoint decryptPoint(ECPair encryption) {
        if (m_blindDecryption) {
            BigInteger blindFactor = m_params.getRandomIndex();
            return encryption.getX().subtract(encryption.getY().multiply(blindFactor.add(m_secretKey)))
                    .add(encryption.getY().multiply(blindFactor));
        } else {
            return encryption.getX().subtract(encryption.getY().multiply(m_secretKey));
        }
    }

    /**
     * Decrypts the specified encryption down to a long representing a balance.
     * This requires first decrypting to a point (using
     * {@link #decryptPoint(ECPair) decryptPoint}) and then solving the discrete
     * log problem on the resulting point. As the discrete log problem is
     * expected to be difficult in the group, we can only solve it for very
     * small discrete log values and we do so using a lookup table stored in the
     * {@link solidus.util.EncryptionParams} object specified at construction
     * time.
     *
     * @param encryption the encryption to decrypt
     * @return the discrete log of the decrypted point relative to the group
     *         generator.
     * @throws IllegalArgumentException if the discrete log is too big to
     *             determine using the lookup table stored in the
     *             {@link solidus.util.EncryptionParams} given at construction.
     */
    public long decryptBalance(ECPair encryption) {
        return m_params.lookupDiscreteLog(decryptPoint(encryption));
    }
}
