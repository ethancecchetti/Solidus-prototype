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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.Objects;

import org.bouncycastle.crypto.ec.ECPair;
import org.bouncycastle.math.ec.ECPoint;

import solidus.io.SerialHelpers;
import solidus.io.SerialWriter;
import solidus.util.EncryptionParams;

/**
 * This is a zero-knowledge proof that two El Gamal ciphertexts encrypt the same
 * plaintext under two different public keys. The party generating the proof
 * must know the plaintext and randomization factors of both ciphertexts (as
 * well as the encryption keys, which are assumed to be public).
 *
 * @author jyamy42@gmail.com
 */

public class PlaintextEqDisKeyProof implements SerialWriter {
    /**
     * Constructs a new proof that two ciphertext encrypt the same plaintext
     * under different public keys.
     *
     * NOTE: If the ciphertext do not, in fact, encrypt the same plaintext under
     * thd given public keys, then the resulting proof will be invalid. However,
     * for efficiency, this method performs no verification.
     *
     * @param params The public encryption parameters
     * @param cipher1 The first ciphertext
     * @param cipher2 The second ciphertext
     * @param publicKey1 The public key used to encrypt {@code cipher1}
     * @param publicKey2 The public key used to encrypt {@code cipher2}
     * @param plaintext The plaintext value encrypted by the two ciphertexts
     * @param rand1 The randomization factor of {@code cipher1}
     * @param rand2 The randomization factor of {@code cipher2}
     * @return A new proof that {@code cipher1} encrypts the same value as
     *         {@code cipher2} under {@code publicKey1} and {@code publicKey2},
     *         respectively.
     */
    public static PlaintextEqDisKeyProof buildProof(EncryptionParams params, ECPair cipher1, ECPair cipher2,
            ECPoint publicKey1, ECPoint publicKey2, BigInteger plaintext, BigInteger rand1, BigInteger rand2) {
        BigInteger e1 = params.getRandomIndex();
        BigInteger e2 = params.getRandomIndex();
        BigInteger e3 = params.getRandomIndex();

        BigInteger c = params.hash(cipher1.getX(), cipher1.getY(), cipher2.getX(), cipher2.getY(), publicKey1,
                publicKey2, params.getGenerator().multiply(e1).add(publicKey1.multiply(e2)),
                params.getGenerator().multiply(e2), params.getGenerator().multiply(e1).add(publicKey2.multiply(e3)),
                params.getGenerator().multiply(e3));

        BigInteger s1 = e1.subtract(c.multiply(plaintext));
        BigInteger s2 = e2.subtract(c.multiply(rand1));
        BigInteger s3 = e3.subtract(c.multiply(rand2));

        return new PlaintextEqDisKeyProof(params, c, s1, s2, s3);
    }

    private final EncryptionParams m_params;

    private final BigInteger m_c;

    private final BigInteger m_s1;
    private final BigInteger m_s2;
    private final BigInteger m_s3;

    private PlaintextEqDisKeyProof(EncryptionParams params, BigInteger c, BigInteger s1, BigInteger s2, BigInteger s3) {
        m_params = params;

        m_c = c;

        m_s1 = s1;
        m_s2 = s2;
        m_s3 = s3;
    }

    /**
     * Verifies that this proof correctly proves that {@code cipher1} and
     * {@code cipher2} encrypt the same values under {@code publicKey1} and
     * {@code publicKey2}, respectively.
     *
     * @param cipher1 The first ciphertext
     * @param cipher2 The second ciphertext
     * @param publicKey1 The public key used to encrypt {@code cipher1}
     * @param publicKey2 The public key used to encrypt {@code cipher2}
     * @return {@code true} if the proof is valid for the given ciphers and
     *         keys, {@code false} otherwise.
     */
    public boolean verify(ECPair cipher1, ECPair cipher2, ECPoint publicKey1, ECPoint publicKey2) {
        BigInteger c = m_params.hash(cipher1.getX(), cipher1.getY(), cipher2.getX(), cipher2.getY(), publicKey1,
                publicKey2,
                cipher1.getX().multiply(m_c).add(m_params.getGenerator().multiply(m_s1).add(publicKey1.multiply(m_s2))),
                cipher1.getY().multiply(m_c).add(m_params.getGenerator().multiply(m_s2)),
                cipher2.getX().multiply(m_c).add(m_params.getGenerator().multiply(m_s1).add(publicKey2.multiply(m_s3))),
                cipher2.getY().multiply(m_c).add(m_params.getGenerator().multiply(m_s3)));

        return c.equals(m_c);
    }

    @Override
    public void serialWriteOut(OutputStream outStream, boolean compressPoints) throws IOException {
        SerialHelpers.writeBigInteger(outStream, m_c);

        SerialHelpers.writeBigInteger(outStream, m_s1);
        SerialHelpers.writeBigInteger(outStream, m_s2);
        SerialHelpers.writeBigInteger(outStream, m_s3);
    }

    public static PlaintextEqDisKeyProof serialReadIn(InputStream inStream, EncryptionParams params)
            throws IOException {
        BigInteger c = SerialHelpers.readBigInteger(inStream);

        BigInteger s1 = SerialHelpers.readBigInteger(inStream);
        BigInteger s2 = SerialHelpers.readBigInteger(inStream);
        BigInteger s3 = SerialHelpers.readBigInteger(inStream);

        return new PlaintextEqDisKeyProof(params, c, s1, s2, s3);
    }

    @Override
    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof PlaintextEqDisKeyProof)) return false;

        PlaintextEqDisKeyProof pf = (PlaintextEqDisKeyProof) o;
        return Objects.equals(m_c, pf.m_c) && Objects.equals(m_s1, pf.m_s1) && Objects.equals(m_s2, pf.m_s2)
                && Objects.equals(m_s3, pf.m_s3);
    }

    @Override
    public int hashCode() {
        return Objects.hash(m_c, m_s1, m_s2, m_s3);
    }
}
