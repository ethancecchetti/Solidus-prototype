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

import org.bouncycastle.crypto.ec.ECPair;
import org.bouncycastle.math.ec.ECPoint;

import solidus.io.SerialHelpers;
import solidus.io.SerialWriter;
import solidus.util.EncryptionParams;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.Objects;

/**
 * This this a zero-knowledge proof that two ElGamal encryptions encrypt the
 * same plaintest.
 *
 * @author ethan@cs.cornell.edu
 */
public class PlaintextEqProof implements SerialWriter {
    private final EncryptionParams m_params;
    private final BigInteger m_c;
    private final BigInteger m_s;

    private PlaintextEqProof(EncryptionParams params, BigInteger c, BigInteger s) {
        m_params = params;
        m_c = c;
        m_s = s;
    }

    /**
     * Generates a zero-knowledge proof that the two ciphertexts encrypt the
     * same value as each other and are encrypted under {@code publicKey}.
     *
     * NOTE: If any of the conditions we are trying to prove are false or if
     * {@code secretKey} is not the associated secret key (i.e., the discrete
     * log of {@code publicKey} with respect to the group generator), then the
     * resulting proof will be invalid. However, for efficiency, this method
     * performs no verification.
     *
     * @param params The public encryption parameters
     * @param cipher1 The first ciphertext
     * @param cipher2 The second ciphertext
     * @param publicKey The public encryption key used to encrypt the
     *            ciphertexts.
     * @param secretKey The secret decryption key for both ciphers and
     *            {@code publicKey}.
     * @return a zk proof that the provided ciphertext encrypt the same
     *         plaintext under the public key.
     */
    public static PlaintextEqProof buildProof(EncryptionParams params, ECPair cipher1, ECPair cipher2,
            ECPoint publicKey, BigInteger secretKey) {
        BigInteger e = params.getRandomIndex();
        ECPoint cipherChallengePoint = cipher1.getY().subtract(cipher2.getY()).multiply(e);
        ECPoint keyChallengePoint = params.getGenerator().multiply(e);

        BigInteger c = params.hash(cipher1.getX(), cipher1.getY(), cipher2.getX(), cipher2.getY(), publicKey,
                cipherChallengePoint, keyChallengePoint);

        BigInteger s = e.subtract(c.multiply(secretKey)).mod(params.getGroupSize());

        return new PlaintextEqProof(params, c, s);
    }

    public static PlaintextEqProof serialReadIn(InputStream inStream, EncryptionParams params) throws IOException {
        BigInteger c = SerialHelpers.readBigInteger(inStream);
        BigInteger s = SerialHelpers.readBigInteger(inStream);
        return new PlaintextEqProof(params, c, s);
    }

    public boolean verify(ECPair cipher1, ECPair cipher2, ECPoint publicKey) {
        ECPoint cipherChallengePoint = cipher1.getX().subtract(cipher2.getX()).multiply(m_c)
                .add(cipher1.getY().subtract(cipher2.getY()).multiply(m_s));
        ECPoint keyChallengePoint = publicKey.multiply(m_c).add(m_params.getGenerator().multiply(m_s));

        BigInteger newC = m_params.hash(cipher1.getX(), cipher1.getY(), cipher2.getX(), cipher2.getY(), publicKey,
                cipherChallengePoint, keyChallengePoint);

        return newC.equals(m_c);
    }

    @Override
    public void serialWriteOut(OutputStream outStream, boolean compressPoints) throws IOException {
        SerialHelpers.writeBigInteger(outStream, m_c);
        SerialHelpers.writeBigInteger(outStream, m_s);
    }

    @Override
    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof PlaintextEqProof)) return false;

        PlaintextEqProof pf = (PlaintextEqProof) o;
        return Objects.equals(m_c, pf.m_c) && Objects.equals(m_s, pf.m_s);
    }

    @Override
    public int hashCode() {
        return Objects.hash(m_c, m_s);
    }
}
