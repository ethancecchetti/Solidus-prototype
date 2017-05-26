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
 * This interface provides the ability to generate El Gamal encryptions under a
 * fixed public key. It may be multi-threaded and compute randomization factors
 * in the background for efficiency.
 *
 * @author ethan@cs.cornell.edu
 */
public interface Encryptor {
    /**
     * @return the public key used for encryption by this Encryptor.
     */
    public ECPoint getPublicKey();

    /**
     * Gets a fresh encryption of the group identity (typically referred to
     * "infinity" or "O" for an elliptic curve group). Since Solidus encrypts
     * balances as multiples of curves, this is the same as encrypting a balance
     * of zero.
     *
     * @return a fresh encryption of the group identity.
     */
    public ECPair encryptZero();

    /**
     * Encrypts the given elliptic curve point as an El Gamal ciphertext.
     *
     * @param point The elliptic curve point to encrypt.
     * @return an El Gamal encryption of {@code point}.
     */
    public ECPair encryptPoint(ECPoint point);

    /**
     * Multiplies the generator by {@code v} and encrypts the resulting point.
     * Note that this operation is not fully reversible.
     *
     * @param v The discrete log of the point to be encrypted.
     * @return an El Gamal encryption of {@code v * G}.
     */
    public ECPair encryptValue(BigInteger v);

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
     */
    public ECPair encryptBalance(long balance);

    /**
     * Re-randomizes the given encryption assuming it is encrypted with the same
     * public key as this Encryptor object. If not, an arbitrary (and
     * un-decryptable) value will be returned.
     *
     * @param encryption an existing El Gamal encryption of any value under the
     *            same public key used by this Encryptor.
     * @return a re-randomized encryption of the same value.
     */
    public ECPair reencrypt(ECPair encryption);
}
