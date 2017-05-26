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
import java.util.List;
import java.util.Objects;

import org.bouncycastle.crypto.ec.ECPair;
import org.bouncycastle.math.ec.ECPoint;

import com.google.common.collect.ImmutableList;

import solidus.io.SerialHelpers;
import solidus.io.SerialWriter;
import solidus.util.EncryptionParams;

/**
 * This class creates a zero-knowledge proof that two pairs of El Gamal
 * ciphertexts (which are each pairs of elliptic curve points) were either
 * swapped or not. This not only proves that the encrypted values did not
 * change, but it proves that they are still paired in the same way they were
 * paired before (and each pair must be in the same internal order). However,
 * the pairs may have swapped places with each other.
 *
 * For efficiency, this implementation does not rely on any other ZK primitives.
 * Instead it implements everything internally to minimize the number of
 * elliptic curve multiplications needed.
 *
 * @author ethan@cs.cornell.edu
 */
public class DoubleSwapProof implements SerialWriter {
    private static final List<Byte> CHALLENGE_INDICES = ImmutableList.of((byte) 0, (byte) 1, (byte) 2);

    /**
     * This is a bucket class for a pair of EC El Gamal cipher texts.
     */
    public interface CipherPair extends SerialWriter {
        public ECPair getCipher1();

        public ECPair getCipher2();
    }

    /**
     * Generates a proof that the two pairs of ciphertext pairs may have been
     * swapped in the case where they were not.
     *
     * NOTE: If {@code postSwap1} and {@code postSwap2} are not valid
     * reencryptions of {@code preSwap1} and {@code preSwap2}, respectively, all
     * under the public key {@code publicKey} or if {@code secretKey} is not the
     * discrete log of {@code publicKey} with respect to the generator specified
     * in {@code params}, then the resulting proof will not be valid.
     *
     * @param params The public encryption parameters
     * @param preSwap1 The first half of the pre-swap pair.
     * @param preSwap2 The second half of the pre-swap pair.
     * @param postSwap1 The first half of the post-swap pair.
     * @param postSwap2 The second half of the post-swap pair.
     * @param publicKey The public encryption key of all provided ciphertexts.
     * @param secretKey The secret decryption key for all of the ciphertexts.
     * @return a new proof that {@code preSwap1} and {@code preSwap2} encrypt
     *         the same plaintexts as {@code postSwap1} and {@code postSwap2}
     *         under {@code publicKey}, but possibly in a different order.
     */
    public static DoubleSwapProof fromFakeSwap(EncryptionParams params, CipherPair preSwap1, CipherPair preSwap2,
            CipherPair postSwap1, CipherPair postSwap2, ECPoint publicKey, BigInteger secretKey) {
        return buildProof(params, preSwap1, preSwap2, postSwap1, postSwap2, publicKey, secretKey, true);
    }

    /**
     * Generates a proof that the two pairs of ciphertext pairs may have been
     * swapped in the case where they were swapped.
     *
     * NOTE: If {@code postSwap2} and {@code postSwap1} are not valid
     * reencryptions of {@code preSwap1} and {@code preSwap2}, respectively, all
     * under the public key {@code publicKey} or if {@code secretKey} is not the
     * discrete log of {@code publicKey} with respect to the generator specified
     * in {@code params}, then the resulting proof will not be valid.
     *
     * @param params The public encryption parameters
     * @param preSwap1 The first half of the pre-swap pair.
     * @param preSwap2 The second half of the pre-swap pair.
     * @param postSwap1 The first half of the post-swap pair.
     * @param postSwap2 The second half of the post-swap pair.
     * @param publicKey The public encryption key of all provided ciphertexts.
     * @param secretKey The secret decryption key for all of the ciphertexts.
     * @return a new proof that {@code preSwap1} and {@code preSwap2} encrypt
     *         the same plaintexts as {@code postSwap1} and {@code postSwap2}
     *         under {@code publicKey}, but possibly in a different order.
     */
    public static DoubleSwapProof fromRealSwap(EncryptionParams params, CipherPair preSwap1, CipherPair preSwap2,
            CipherPair postSwap1, CipherPair postSwap2, ECPoint publicKey, BigInteger secretKey) {
        return buildProof(params, preSwap1, preSwap2, postSwap1, postSwap2, publicKey, secretKey, false);
    }

    /**
     * Generates a proof tha tthe two pairs of ciphertext pairs may or may not
     * have been swapped. If {@code isFake} is {@code true}, they must not been
     * swapped. If it is {@code false}, they must have been swapped.
     *
     * NOTE: If {@code postSwap1} and {@code postSwap2} are not valid
     * reencryptions of {@code preSwap1} and {@code preSwap2}, (respectively or
     * anti-respectively, depending on the value of {@code isFake}), all under
     * the public key {@code publicKey} or if {@code secretKey} is not the
     * discrete log of {@code publicKey} with respect to the generator specified
     * in {@code params}, then the resulting proof will not be valid.
     *
     * @param params The public encryption parameters
     * @param preSwap1 The first half of the pre-swap pair.
     * @param preSwap2 The second half of the pre-swap pair.
     * @param postSwap1 The first half of the post-swap pair.
     * @param postSwap2 The second half of the post-swap pair.
     * @param publicKey The public encryption key of all provided ciphertexts.
     * @param secretKey The secret decryption key for all of the ciphertexts.
     * @param isFake Whether or not the plaintexts were actually swapped.
     * @return a new proof that {@code preSwap1} and {@code preSwap2} encrypt
     *         the same plaintexts as {@code postSwap1} and {@code postSwap2}
     *         under {@code publicKey}, but possibly in a different order.
     */
    public static DoubleSwapProof buildProof(EncryptionParams params, CipherPair preSwap1, CipherPair preSwap2,
            CipherPair postSwap1, CipherPair postSwap2, ECPoint publicKey, BigInteger secretKey, boolean isFake) {
        List<BigInteger> multipliers = _getChallenges(params, preSwap1, preSwap2, postSwap1, postSwap2, publicKey);
        BigInteger e1 = multipliers.get(0);
        BigInteger e2 = multipliers.get(1);
        BigInteger e3 = multipliers.get(2);

        BigInteger andE = params.getRandomIndex();

        ECPoint andOmegaPiece1 = preSwap1.getCipher1().getY().add(preSwap2.getCipher1().getY())
                .subtract(postSwap1.getCipher1().getY()).subtract(postSwap2.getCipher1().getY())
                .multiply(e1.multiply(andE));
        ECPoint andOmegaPiece2 = preSwap1.getCipher2().getY().add(preSwap2.getCipher2().getY())
                .subtract(postSwap1.getCipher2().getY()).subtract(postSwap2.getCipher2().getY())
                .multiply(e2.multiply(andE));
        ECPoint andOmega = andOmegaPiece1.add(andOmegaPiece2).add(params.getGenerator().multiply(e3.multiply(andE)));

        BigInteger andC = params.hash(andOmega);
        BigInteger andS = andC.multiply(secretKey).add(andE).mod(params.getGroupSize());

        ECPoint orG1Piece1 = preSwap1.getCipher1().getY().subtract(postSwap1.getCipher1().getY());
        ECPoint orG1Piece2 = preSwap1.getCipher2().getY().subtract(postSwap1.getCipher2().getY());

        ECPoint orG2Piece1 = preSwap1.getCipher1().getY().subtract(postSwap2.getCipher1().getY());
        ECPoint orG2Piece2 = preSwap1.getCipher2().getY().subtract(postSwap2.getCipher2().getY());

        BigInteger orE = params.getRandomIndex();
        BigInteger orRandS = params.getRandomIndex();
        BigInteger orRandC = params.getRandomIndex();

        ECPoint orOmega1, orOmega2;
        if (isFake) {
            // omega1 = e1 G1
            orOmega1 = orG1Piece1.multiply(e1.multiply(orE)).add(orG1Piece2.multiply(e2.multiply(orE)))
                    .add(params.getGenerator().multiply(e3.multiply(orE)));

            // omega2 = s2 G2 + c2 Y2
            ECPoint orY2Piece1 = preSwap1.getCipher1().getX().subtract(postSwap2.getCipher1().getX());
            ECPoint orY2Piece2 = preSwap1.getCipher2().getX().subtract(postSwap2.getCipher2().getX());
            orOmega2 = orG2Piece1.multiply(e1.multiply(orRandS)).add(orG2Piece2.multiply(e2.multiply(orRandS)))
                    .add(params.getGenerator().multiply(e3.multiply(orRandS)))
                    .add(orY2Piece1.multiply(e1.multiply(orRandC))).add(orY2Piece2.multiply(e2.multiply(orRandC)))
                    .add(publicKey.multiply(e3.multiply(orRandC)));
        } else {
            // omega1 = s1 G1 + c1 Y1
            ECPoint orY1Piece1 = preSwap1.getCipher1().getX().subtract(postSwap1.getCipher1().getX());
            ECPoint orY1Piece2 = preSwap1.getCipher2().getX().subtract(postSwap1.getCipher2().getX());
            orOmega1 = orG1Piece1.multiply(e1.multiply(orRandS)).add(orG1Piece2.multiply(e2.multiply(orRandS)))
                    .add(params.getGenerator().multiply(e3.multiply(orRandS)))
                    .add(orY1Piece1.multiply(e1.multiply(orRandC))).add(orY1Piece2.multiply(e2.multiply(orRandC)))
                    .add(publicKey.multiply(e3.multiply(orRandC)));

            // omega2 = e2 G2
            orOmega2 = orG2Piece1.multiply(e1.multiply(orE)).add(orG2Piece2.multiply(e2.multiply(orE)))
                    .add(params.getGenerator().multiply(e3.multiply(orE)));
        }
        BigInteger orDetC = params.hash(orOmega1, orOmega2).subtract(orRandC).mod(params.getGroupSize());
        BigInteger orDetS = orE.subtract(orDetC.multiply(secretKey)).mod(params.getGroupSize());

        BigInteger orC1, orS1, orS2;
        if (isFake) {
            orC1 = orDetC;
            orS1 = orDetS;
            orS2 = orRandS;
        } else {
            orC1 = orRandC;
            orS1 = orRandS;
            orS2 = orDetS;
        }

        return new DoubleSwapProof(params, andOmega, andS, orOmega1, orOmega2, orC1, orS1, orS2);
    }

    private static List<BigInteger> _getChallenges(EncryptionParams params, CipherPair preSwap1, CipherPair preSwap2,
            CipherPair postSwap1, CipherPair postSwap2, ECPoint publicKey) {
        return params.hashEachIndexWithAllPoints(CHALLENGE_INDICES, preSwap1.getCipher1().getX(),
                preSwap1.getCipher1().getY(), preSwap1.getCipher2().getX(), preSwap1.getCipher2().getY(),

                preSwap2.getCipher1().getX(), preSwap2.getCipher1().getY(), preSwap2.getCipher2().getX(),
                preSwap2.getCipher2().getY(),

                postSwap1.getCipher1().getX(), postSwap1.getCipher1().getY(), postSwap1.getCipher2().getX(),
                postSwap1.getCipher2().getY(),

                postSwap2.getCipher1().getX(), postSwap2.getCipher1().getY(), postSwap2.getCipher2().getX(),
                postSwap2.getCipher2().getY(),

                publicKey);
    }

    private final EncryptionParams m_params;

    private final ECPoint m_andOmega;
    private final BigInteger m_andS;

    private final ECPoint m_orOmega1;
    private final ECPoint m_orOmega2;
    private final BigInteger m_orC1;
    private final BigInteger m_orS1;
    private final BigInteger m_orS2;

    private DoubleSwapProof(EncryptionParams params, ECPoint andOmega, BigInteger andS, ECPoint orOmega1,
            ECPoint orOmega2, BigInteger orC1, BigInteger orS1, BigInteger orS2) {
        m_params = params;

        m_andOmega = andOmega;
        m_andS = andS;

        m_orOmega1 = orOmega1;
        m_orOmega2 = orOmega2;
        m_orC1 = orC1;
        m_orS1 = orS1;
        m_orS2 = orS2;
    }

    /**
     * Verifies that this proof proves the provided ciphertexts encrypt the same
     * plaintexts (possibly in a different order) under the supplied public key.
     *
     * @param preSwap1 The first half of the pre-swap pair.
     * @param preSwap2 The second half of the pre-swap pair.
     * @param postSwap1 The first half of the post-swap pair.
     * @param postSwap2 The second half of the post-swap pair.
     * @param publicKey The public encryption key of all provided ciphertexts.
     * @return if this proof correctly proves that the ciphertexts encrypt the
     *         same plaintexts, possibly in a different order.
     */
    public boolean verify(CipherPair preSwap1, CipherPair preSwap2, CipherPair postSwap1, CipherPair postSwap2,
            ECPoint publicKey) {
        List<BigInteger> multipliers = _getChallenges(m_params, preSwap1, preSwap2, postSwap1, postSwap2, publicKey);
        return _checkAndProof(multipliers, preSwap1, preSwap2, postSwap1, postSwap2, publicKey)
                && _checkOrProof(multipliers, preSwap1, preSwap2, postSwap1, postSwap2, publicKey);
    }

    private boolean _checkAndProof(List<BigInteger> multipliers, CipherPair preSwap1, CipherPair preSwap2,
            CipherPair postSwap1, CipherPair postSwap2, ECPoint publicKey) {
        BigInteger e1 = multipliers.get(0);
        BigInteger e2 = multipliers.get(1);
        BigInteger e3 = multipliers.get(2);
        BigInteger c = m_params.hash(m_andOmega);

        ECPoint targetPiece1 = preSwap1.getCipher1().getX().add(preSwap2.getCipher1().getX())
                .subtract(postSwap1.getCipher1().getX().add(postSwap2.getCipher1().getX()));
        ECPoint targetPiece2 = preSwap1.getCipher2().getX().add(preSwap2.getCipher2().getX())
                .subtract(postSwap1.getCipher2().getX().add(postSwap2.getCipher2().getX()));
        ECPoint cYPlusOmega = targetPiece1.multiply(e1.multiply(c)).add(targetPiece2.multiply(e2.multiply(c)))
                .add(publicKey.multiply(e3.multiply(c))).add(m_andOmega);

        ECPoint basePiece1 = preSwap1.getCipher1().getY().add(preSwap2.getCipher1().getY())
                .subtract(postSwap1.getCipher1().getY().add(postSwap2.getCipher1().getY()));
        ECPoint basePiece2 = preSwap1.getCipher2().getY().add(preSwap2.getCipher2().getY())
                .subtract(postSwap1.getCipher2().getY().add(postSwap2.getCipher2().getY()));
        ECPoint sG = basePiece1.multiply(e1.multiply(m_andS)).add(basePiece2.multiply(e2.multiply(m_andS)))
                .add(m_params.getGenerator().multiply(e3.multiply(m_andS)));

        return cYPlusOmega.equals(sG);
    }

    private boolean _checkOrProof(List<BigInteger> multipliers, CipherPair preSwap1, CipherPair preSwap2,
            CipherPair postSwap1, CipherPair postSwap2, ECPoint publicKey) {
        BigInteger e1 = multipliers.get(0);
        BigInteger e2 = multipliers.get(1);
        BigInteger e3 = multipliers.get(2);

        ECPoint orG1Piece1 = preSwap1.getCipher1().getY().subtract(postSwap1.getCipher1().getY());
        ECPoint orG1Piece2 = preSwap1.getCipher2().getY().subtract(postSwap1.getCipher2().getY());

        ECPoint orG2Piece1 = preSwap1.getCipher1().getY().subtract(postSwap2.getCipher1().getY());
        ECPoint orG2Piece2 = preSwap1.getCipher2().getY().subtract(postSwap2.getCipher2().getY());

        ECPoint orY1Piece1 = preSwap1.getCipher1().getX().subtract(postSwap1.getCipher1().getX());
        ECPoint orY1Piece2 = preSwap1.getCipher2().getX().subtract(postSwap1.getCipher2().getX());

        ECPoint orY2Piece1 = preSwap1.getCipher1().getX().subtract(postSwap2.getCipher1().getX());
        ECPoint orY2Piece2 = preSwap1.getCipher2().getX().subtract(postSwap2.getCipher2().getX());

        BigInteger c2 = m_params.hash(m_orOmega1, m_orOmega2).subtract(m_orC1).mod(m_params.getGroupSize());

        ECPoint omega1MinusS1G1 = m_orOmega1
                .subtract(orG1Piece1.multiply(e1.multiply(m_orS1)).add(orG1Piece2.multiply(e2.multiply(m_orS1)))
                        .add(m_params.getGenerator().multiply(e3.multiply(m_orS1))));
        ECPoint c1Y1 = orY1Piece1.multiply(e1.multiply(m_orC1)).add(orY1Piece2.multiply(e2.multiply(m_orC1)))
                .add(publicKey.multiply(e3.multiply(m_orC1)));

        ECPoint omega2MinusS2G2 = m_orOmega2
                .subtract(orG2Piece1.multiply(e1.multiply(m_orS2)).add(orG2Piece2.multiply(e2.multiply(m_orS2)))
                        .add(m_params.getGenerator().multiply(e3.multiply(m_orS2))));
        ECPoint c2Y2 = orY2Piece1.multiply(e1.multiply(c2)).add(orY2Piece2.multiply(e2.multiply(c2)))
                .add(publicKey.multiply(e3.multiply(c2)));

        return omega1MinusS1G1.equals(c1Y1) && omega2MinusS2G2.equals(c2Y2);
    }

    @Override
    public void serialWriteOut(OutputStream outStream, boolean compressPoints) throws IOException {
        SerialHelpers.writeECPoint(outStream, m_andOmega, compressPoints);
        SerialHelpers.writeBigInteger(outStream, m_andS);

        SerialHelpers.writeECPoint(outStream, m_orOmega1, compressPoints);
        SerialHelpers.writeECPoint(outStream, m_orOmega2, compressPoints);
        SerialHelpers.writeBigInteger(outStream, m_orC1);
        SerialHelpers.writeBigInteger(outStream, m_orS1);
        SerialHelpers.writeBigInteger(outStream, m_orS2);
    }

    public static DoubleSwapProof serialReadIn(InputStream inStream, EncryptionParams params) throws IOException {
        ECPoint andOmega = SerialHelpers.readECPoint(inStream, params);
        BigInteger andS = SerialHelpers.readBigInteger(inStream);

        ECPoint orOmega1 = SerialHelpers.readECPoint(inStream, params);
        ECPoint orOmega2 = SerialHelpers.readECPoint(inStream, params);
        BigInteger orC1 = SerialHelpers.readBigInteger(inStream);
        BigInteger orS1 = SerialHelpers.readBigInteger(inStream);
        BigInteger orS2 = SerialHelpers.readBigInteger(inStream);

        return new DoubleSwapProof(params, andOmega, andS, orOmega1, orOmega2, orC1, orS1, orS2);
    }

    @Override
    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof DoubleSwapProof)) return false;

        DoubleSwapProof pf = (DoubleSwapProof) o;
        return Objects.equals(m_andOmega, pf.m_andOmega) && Objects.equals(m_andS, pf.m_andS)
                && Objects.equals(m_orOmega1, pf.m_orOmega1) && Objects.equals(m_orOmega2, pf.m_orOmega2)
                && Objects.equals(m_orC1, pf.m_orC1) && Objects.equals(m_orS1, pf.m_orS1)
                && Objects.equals(m_orS2, pf.m_orS2);
    }

    @Override
    public int hashCode() {
        return Objects.hash(m_andOmega, m_andS, m_orOmega1, m_orOmega2, m_orC1, m_orS1, m_orS2);
    }
}
