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
import solidus.util.EncryptionParams;

public class ProofOfKnowledgeOfRep implements Signature {
    public static ProofOfKnowledgeOfRep buildProof(EncryptionParams params, ECPair cipher, ECPoint publicKey,
            BigInteger messageMultiple, BigInteger randomness, byte[]... messageParts) {
        BigInteger e1 = params.getRandomIndex();
        BigInteger e2 = params.getRandomIndex();

        ECPoint combinedPoint = params.getGenerator().multiply(e1.add(e2)).add(publicKey.multiply(e2)).normalize();

        BigInteger c = params.hashDataAndPoints(messageParts, cipher.getX(), cipher.getY(), publicKey, combinedPoint);

        BigInteger s1 = messageMultiple.multiply(c).add(e1).mod(params.getGroupSize());
        BigInteger s2 = randomness.multiply(c).add(e2).mod(params.getGroupSize());

        return new ProofOfKnowledgeOfRep(params, cipher, combinedPoint, s1, s2);
    }

    private final EncryptionParams m_params;

    private final ECPair m_cipher;
    private final ECPoint m_combinedPoint;
    private final BigInteger m_s1;
    private final BigInteger m_s2;

    private ProofOfKnowledgeOfRep(EncryptionParams params, ECPair cipher, ECPoint combinedPoint, BigInteger s1,
            BigInteger s2) {
        m_params = params;

        m_cipher = cipher;
        m_combinedPoint = combinedPoint;
        m_s1 = s1;
        m_s2 = s2;
    }

    public ECPair getCipher() {
        return m_cipher;
    }

    @Override
    public boolean verify(ECPoint verificationKey, byte[]... messageParts) {
        BigInteger c = m_params.hashDataAndPoints(messageParts, m_cipher.getX(), m_cipher.getY(), verificationKey,
                m_combinedPoint);

        ECPoint point1 = m_cipher.getX().add(m_cipher.getY()).multiply(c).add(m_combinedPoint);
        ECPoint point2 = m_params.getGenerator().multiply(m_s1.add(m_s2)).add(verificationKey.multiply(m_s2));
        return point1.equals(point2);
    }

    @Override
    public void serialWriteOut(OutputStream outStream, boolean compressPoints) throws IOException {
        SerialHelpers.writeECPair(outStream, m_cipher, compressPoints);
        SerialHelpers.writeECPoint(outStream, m_combinedPoint, compressPoints);
        SerialHelpers.writeBigInteger(outStream, m_s1);
        SerialHelpers.writeBigInteger(outStream, m_s2);
    }

    public static ProofOfKnowledgeOfRep serialReadIn(InputStream inStream, EncryptionParams params) throws IOException {
        ECPair cipher = SerialHelpers.readECPair(inStream, params);
        ECPoint combinedPoint = SerialHelpers.readECPoint(inStream, params);
        BigInteger s1 = SerialHelpers.readBigInteger(inStream);
        BigInteger s2 = SerialHelpers.readBigInteger(inStream);

        return new ProofOfKnowledgeOfRep(params, cipher, combinedPoint, s1, s2);
    }

    @Override
    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof ProofOfKnowledgeOfRep)) return false;

        ProofOfKnowledgeOfRep pf = (ProofOfKnowledgeOfRep) o;
        return Objects.equals(m_cipher, pf.m_cipher) && Objects.equals(m_combinedPoint, pf.m_combinedPoint)
                && Objects.equals(m_s1, pf.m_s1) && Objects.equals(m_s2, pf.m_s2);
    }

    @Override
    public int hashCode() {
        return Objects.hash(m_cipher, m_combinedPoint, m_s1, m_s2);
    }
}
