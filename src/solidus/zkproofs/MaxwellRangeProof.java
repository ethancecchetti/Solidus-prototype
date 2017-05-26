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

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;

import com.google.common.collect.ImmutableList;

import org.bouncycastle.crypto.ec.ECPair;
import org.bouncycastle.math.ec.ECPoint;

import solidus.io.SerialHelpers;
import solidus.io.SerialWriter;

import solidus.util.EncryptionParams;
import solidus.util.Encryptor;
import solidus.util.Utils;

/**
 * Creates a proof that an El Gamal ciphertext encrypts a value {@code v} such
 * that {@code 0 &lt; v &lt; N}, where {@code N = 2^t} for some {@code t}. The
 * proof operates by proving that the plaintext can be represented in binary
 * with at most {@code t} bits. It then homomorphically combines ciphertexts of
 * each individual bit and proves that the resulting ciphertext encrypts the
 * same plaintext as the original cipher.
 *
 * These proofs are quite large, and it is possible to generate and verify the
 * proofs for each bit independently. This class contains utilities to perform
 * those operations in a multithreaded fashion if given an {@code
 * ExecutorService} to spawn new tasks.
 *
 * Created by fanz on 10/5/16.
 */

public class MaxwellRangeProof implements SerialWriter {
    private static final List<Byte> CHALLENGE_INDEX_LIST = ImmutableList.of((byte) 0, (byte) 1);

    /**
     * Constructs a new range proof that {@code cipher} encrypts a value of at
     * most {@code t} bits. The actual value ({@code value}) is required to
     * generate this proof.
     *
     * This method is single-threaded.
     *
     * NOTE: if any of the conditions of this proof are false (e.g., {@code
     * cipher} is not a ciphertext under {@code publicKey}, {@code secretKey} is
     * not the decryption key associated with {@code publicKey}, {@code
     * cipher} encrypts a value that is too large, etc), the resulting proof
     * will be invalid. However, for efficiency, this method performs no
     * verification!
     *
     * @param params The public encryption parameters
     * @param cipher The ciphertext to generate the range proof on
     * @param value The plaintext value that is sufficiently small.
     * @param publicKey The public encryption key used to encrypt {@code cipher}
     * @param secretKey The secret decryption key associated with
     *            {@code publicKey}
     * @return A proof that {@code cipher} is a valid ciphertext under
     *         {@code publicKey} encrypting a non-negative value that's binary
     *         representation is at most
     *         {@link solidus.util.EncryptionParams#getMaxDiscreteLogBits
     *         params.getMaxDiscreteLogBits()} bits.
     * @see #buildProof(EncryptionParams, ECPair, long, ECPoint, BigInteger,
     *      ExecutorService)
     */
    public static MaxwellRangeProof buildProof(EncryptionParams params, ECPair cipher, long value, ECPoint publicKey,
            BigInteger secretKey) {
        return buildProof(params, cipher, value, publicKey, secretKey, null);
    }

    /**
     * Constructs a new range proof that {@code cipher} encrypts a value of at
     * most {@code t} bits. The actual value ({@code value}) is required to
     * generate this proof.
     *
     * If an ExecutorService object is provided, it will be given tasks so that
     * independent parts of the proof can be generated in parallel. If {@code
     * executor} is {@code null}, the proof will be generated in single-threaded
     * mode.
     *
     * NOTE: if any of the conditions of this proof are false (e.g., {@code
     * cipher} is not a ciphertext under {@code publicKey}, {@code secretKey} is
     * not the decryption key associated with {@code publicKey}, {@code
     * cipher} encrypts a value that is too large, etc), the resulting proof
     * will be invalid. However, for efficiency, this method performs no
     * verification!
     *
     * @param params The public encryption parameters
     * @param cipher The ciphertext to generate the range proof on
     * @param value The plaintext value that is sufficiently small.
     * @param publicKey The public encryption key used to encrypt {@code cipher}
     * @param secretKey The secret decryption key associated with
     *            {@code publicKey}
     * @param executor The executor service used to spawn new tasks. If this is
     *            {@code null}, the operation will be run single-threaded.
     * @return A proof that {@code cipher} is a valid ciphertext under
     *         {@code publicKey} encrypting a non-negative value that's binary
     *         representation is at most
     *         {@link solidus.util.EncryptionParams#getMaxDiscreteLogBits
     *         params.getMaxDiscreteLogBits()} bits.
     * @see #buildProof(EncryptionParams, ECPair, long, ECPoint, BigInteger)
     */
    public static MaxwellRangeProof buildProof(EncryptionParams params, ECPair cipher, long value, ECPoint publicKey,
            BigInteger secretKey, ExecutorService executor) {
        Encryptor encryptor = params.getEncryptor(publicKey);

        List<BigInteger> multipliers = params.hashEachIndexWithAllPoints(CHALLENGE_INDEX_LIST, cipher.getX(),
                cipher.getY(), publicKey);
        BigInteger e1 = multipliers.get(0);
        BigInteger e2 = multipliers.get(1);
        ECPoint genE1 = params.getGenerator().multiply(e1);
        ECPoint genE2 = params.getGenerator().multiply(e2);
        ECPoint pubKeyE2 = publicKey.multiply(e2);

        List<Future<ProofAndMultiple>> proofFutureList = new ArrayList<>();
        ImmutableList.Builder<ECPair> encryptedBitsBuilder = new ImmutableList.Builder<>();

        for (int i = 0; i < params.getMaxDiscreteLogBits(); i++) {
            final ECPair bitCipher;
            boolean bitIsSet = ((value & (1 << i)) != 0);
            if (bitIsSet) {
                bitCipher = encryptor.encryptPoint(params.getGenerator());
            } else {
                bitCipher = encryptor.encryptZero();
            }

            Callable<ProofAndMultiple> bitProver = new OneBitProver(params, bitIsSet, bitCipher, e1, pubKeyE2, genE1,
                    genE2, publicKey, secretKey, i);
            proofFutureList.add(Utils.submitJob(bitProver, executor));
            encryptedBitsBuilder.add(bitCipher);
        }

        ImmutableList.Builder<OneOfTwoDlogProof> orProofListBuilder = new ImmutableList.Builder<>();
        ECPoint aSum = params.getInfinity();
        ECPoint bSum = params.getInfinity();
        for (Future<ProofAndMultiple> future : proofFutureList) {
            ProofAndMultiple proofAndMultiple = Utils.getFuture(future);
            orProofListBuilder.add(proofAndMultiple.m_proof);
            aSum = aSum.add(proofAndMultiple.m_xMultiple);
            bSum = bSum.add(proofAndMultiple.m_yMultiple);
        }

        PlaintextEqProof eqProof = PlaintextEqProof.buildProof(params, new ECPair(aSum, bSum), cipher, publicKey,
                secretKey);
        return new MaxwellRangeProof(params, eqProof, orProofListBuilder.build(), encryptedBitsBuilder.build());
    }

    public static MaxwellRangeProof serialReadIn(InputStream inStream, EncryptionParams params) throws IOException {
        PlaintextEqProof eqProof = PlaintextEqProof.serialReadIn(inStream, params);

        int proofListLength = inStream.read();
        if (proofListLength < 0) throw new EOFException("Unexpected end of file in MaxwellRangeProof");
        if (proofListLength == 0) throw new RuntimeException("Invalid MaxwellRangeProof encoding. Zero proofs");

        ImmutableList.Builder<OneOfTwoDlogProof> orProofListBuilder = new ImmutableList.Builder<>();
        ImmutableList.Builder<ECPair> encryptedBitsBuilder = new ImmutableList.Builder<>();
        for (int i = 0; i < proofListLength; i++) {
            orProofListBuilder.add(OneOfTwoDlogProof.serialReadIn(inStream, params));

            encryptedBitsBuilder.add(SerialHelpers.readECPair(inStream, params));
        }

        return new MaxwellRangeProof(params, eqProof, orProofListBuilder.build(), encryptedBitsBuilder.build());
    }

    private final EncryptionParams m_params;

    private final PlaintextEqProof m_eqProof;
    private final List<OneOfTwoDlogProof> m_orProofList;
    private final List<ECPair> m_encryptedBits;

    private MaxwellRangeProof(EncryptionParams params, PlaintextEqProof eqProof, List<OneOfTwoDlogProof> orProofList,
            List<ECPair> encryptedBits) {
        m_params = params;

        m_eqProof = eqProof;
        m_orProofList = orProofList;
        m_encryptedBits = encryptedBits;
    }

    /**
     * @return The number of bits used to represent the plaintext value,
     *         bounding its size.
     */
    public int getNumberOfBits() {
        return m_encryptedBits.size();
    }

    /**
     * Verifies that this is a valid range proof on the provided ciphertext
     * encrypted under the provided public encryption key.
     *
     * This method performs all verification within the current thread.
     *
     * @param cipher The ciphertext that this proves is in the valid range.
     * @param publicKey Public encryption key used to encrypt {@code cipher}.
     * @return {@code true} if the proof is valid for {@code cipher} and
     *         {@code publicKey}, {@code false} otherwise.
     */
    public boolean verify(ECPair cipher, ECPoint publicKey) {
        return verify(cipher, publicKey, null);
    }

    /**
     * Verifies that this is a valid range proof on the provided ciphertext
     * encrypted under the provided public encryption key.
     *
     * This method uses the provided thread pool to verify components and
     * perform operations in parallel. If the {@code executor} argument is
     * {@code null}, everything is verified in the current thread.
     *
     * @param cipher The ciphertext that this proves is in the valid range.
     * @param publicKey Public encryption key used to encrypt {@code cipher}.
     * @param executor The thread pool to use for parallelizing verification or
     *            {@code null} if all verification should be performed in the
     *            current thread.
     * @return {@code true} if the proof is valid for {@code cipher} and
     *         {@code publicKey}, {@code false} otherwise.
     */
    public boolean verify(ECPair cipher, ECPoint publicKey, ExecutorService executor) {
        if (m_encryptedBits.size() != m_orProofList.size()) return false;

        ECPoint aSum = m_params.getInfinity();
        ECPoint bSum = m_params.getInfinity();

        int bitIndex = 0;
        for (ECPair encryptedBit : m_encryptedBits) {
            aSum = aSum.add(encryptedBit.getX().timesPow2(bitIndex));
            bSum = bSum.add(encryptedBit.getY().timesPow2(bitIndex));
            bitIndex++;
        }

        if (!m_eqProof.verify(new ECPair(aSum, bSum), cipher, publicKey)) {
            return false;
        }

        List<BigInteger> multipliers = m_params.hashEachIndexWithAllPoints(CHALLENGE_INDEX_LIST, cipher.getX(),
                cipher.getY(), publicKey);
        BigInteger e1 = multipliers.get(0);
        BigInteger e2 = multipliers.get(1);

        ECPoint genE1 = m_params.getGenerator().multiply(e1);
        ECPoint genE2 = m_params.getGenerator().multiply(e2);
        ECPoint pubKeyE2 = publicKey.multiply(e2);

        List<Future<Boolean>> verificationFutureList = new ArrayList<>();

        for (int i = 0; i < m_encryptedBits.size(); i++) {
            Callable<Boolean> orProofVerifier = new OneBitVerifier(m_orProofList.get(i), m_encryptedBits.get(i), e1,
                    pubKeyE2, genE1, genE2, publicKey);
            verificationFutureList.add(Utils.submitJob(orProofVerifier, executor));
        }

        return (verificationFutureList.stream().allMatch(Utils::getFuture));
    }

    @Override
    public void serialWriteOut(OutputStream outStream, boolean compressPoints) throws IOException {
        m_eqProof.serialWriteOut(outStream, compressPoints);

        if (m_orProofList.size() > 0xff)
            throw new RuntimeException("Or proof list somehow had more than 255 elements.");

        outStream.write(m_orProofList.size());
        for (int i = 0; i < m_orProofList.size(); i++) {
            m_orProofList.get(i).serialWriteOut(outStream, compressPoints);
            SerialHelpers.writeECPair(outStream, m_encryptedBits.get(i), compressPoints);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof MaxwellRangeProof)) return false;

        MaxwellRangeProof pf = (MaxwellRangeProof) o;
        return Objects.equals(m_eqProof, pf.m_eqProof) && Objects.equals(m_orProofList, pf.m_orProofList)
                && Objects.equals(m_encryptedBits, pf.m_encryptedBits);
    }

    @Override
    public int hashCode() {
        return Objects.hash(m_eqProof, m_orProofList, m_encryptedBits);
    }

    private static class ProofAndMultiple {
        private final OneOfTwoDlogProof m_proof;
        private final ECPoint m_xMultiple;
        private final ECPoint m_yMultiple;

        private ProofAndMultiple(OneOfTwoDlogProof proof, ECPoint xMultiple, ECPoint yMultiple) {
            m_proof = proof;
            m_xMultiple = xMultiple;
            m_yMultiple = yMultiple;
        }
    }

    private static class OneBitProver implements Callable<ProofAndMultiple> {
        private final EncryptionParams params;
        private final boolean bit;
        private final ECPair cipherOfBit;
        private final BigInteger e1;
        private final ECPoint pubKeyE2;
        private final ECPoint genE1;
        private final ECPoint genE2;
        private final ECPoint publicKey;
        private final BigInteger secretKey;
        private final int powerOfTwo;

        private OneBitProver(EncryptionParams params, boolean bit, ECPair cipherOfBit, BigInteger e1, ECPoint pubKeyE2,
                ECPoint genE1, ECPoint genE2, ECPoint publicKey, BigInteger secretKey, int powerOfTwo) {
            this.params = params;
            this.bit = bit;
            this.cipherOfBit = cipherOfBit;
            this.e1 = e1;
            this.pubKeyE2 = pubKeyE2;
            this.genE1 = genE1;
            this.genE2 = genE2;
            this.publicKey = publicKey;
            this.secretKey = secretKey;
            this.powerOfTwo = powerOfTwo;
        }

        @Override
        public ProofAndMultiple call() throws Exception {
            ECPoint bitZeroCaseX = cipherOfBit.getX().multiply(e1).add(pubKeyE2);
            ECPoint bitOneCaseX = bitZeroCaseX.subtract(genE1);
            ECPoint logBase = cipherOfBit.getY().multiply(e1).add(genE2);

            // b == 0; Ai = riY = x riG = xBi;
            // b == 1: Ai = xiG + riY = G + xriG => Ai - G = xBi;
            OneOfTwoDlogProof proof = OneOfTwoDlogProof.buildProof(params, logBase, bitZeroCaseX, bitOneCaseX,
                    publicKey, secretKey, !bit);

            ECPoint xMultiple = cipherOfBit.getX().timesPow2(powerOfTwo);
            ECPoint yMultiple = cipherOfBit.getY().timesPow2(powerOfTwo);
            return new ProofAndMultiple(proof, xMultiple, yMultiple);
        }
    }

    private static class OneBitVerifier implements Callable<Boolean> {
        private final OneOfTwoDlogProof orProof;
        private final ECPair cipherOfBit;
        private final BigInteger e1;
        private final ECPoint pubKeyE2;
        private final ECPoint genE1;
        private final ECPoint genE2;
        private final ECPoint publicKey;

        public OneBitVerifier(OneOfTwoDlogProof orProof, ECPair cipherOfBit, BigInteger e1, ECPoint pubKeyE2,
                ECPoint genE1, ECPoint genE2, ECPoint publicKey) {
            this.orProof = orProof;
            this.cipherOfBit = cipherOfBit;
            this.e1 = e1;
            this.pubKeyE2 = pubKeyE2;
            this.genE1 = genE1;
            this.genE2 = genE2;
            this.publicKey = publicKey;
        }

        @Override
        public Boolean call() throws Exception {
            ECPoint bitZeroCaseX = cipherOfBit.getX().multiply(e1).add(pubKeyE2);
            ECPoint bitOneCaseX = bitZeroCaseX.subtract(genE1);
            ECPoint eitherCaseY = cipherOfBit.getY().multiply(e1).add(genE2);

            return orProof.verify(eitherCaseY, bitZeroCaseX, bitOneCaseX, publicKey);
        }
    }
}
