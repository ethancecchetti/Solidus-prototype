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
 * Created by fanz on 10/5/16. ZK-PoK { x : ((A=xB OR AA = xB)) AND Y=xG}
 */
public class OneOfTwoDlogProof implements SerialWriter {
    private final EncryptionParams m_params;

    private final BigInteger m_c1;
    private final BigInteger m_c2;
    private final BigInteger m_s1;
    private final BigInteger m_s2;

    private OneOfTwoDlogProof(EncryptionParams params, BigInteger c1, BigInteger c2, BigInteger s1, BigInteger s2) {
        m_params = params;

        m_c1 = c1;
        m_c2 = c2;
        m_s1 = s1;
        m_s2 = s2;
    }

    public static OneOfTwoDlogProof buildProofFromFirst(EncryptionParams params, ECPoint base, ECPoint point1,
            ECPoint point2, ECPoint publicKey, BigInteger secretKey) {
        return buildProof(params, base, point1, point2, publicKey, secretKey, true);
    }

    public static OneOfTwoDlogProof buildProofFromSecond(EncryptionParams params, ECPoint base, ECPoint point1,
            ECPoint point2, ECPoint publicKey, BigInteger secretKey) {
        return buildProof(params, base, point1, point2, publicKey, secretKey, false);
    }

    public static OneOfTwoDlogProof buildProof(EncryptionParams params, ECPoint base, ECPoint point1, ECPoint point2,
            ECPoint publicKey, BigInteger secretKey, boolean isFirst) {
        BigInteger e1 = params.getRandomIndex();
        BigInteger e2 = params.getRandomIndex();

        BigInteger r = params.getRandomIndex();

        ECPoint basePoint1 = base.multiply(e1);
        ECPoint keyPoint1 = params.getGenerator().multiply(e1);
        ECPoint basePoint2 = base.multiply(e2);
        ECPoint keyPoint2 = params.getGenerator().multiply(e2);
        if (isFirst) {
            basePoint2 = basePoint2.add(point2.multiply(r));
            keyPoint2 = keyPoint2.add(publicKey.multiply(r));
        } else {
            basePoint1 = basePoint1.add(point1.multiply(r));
            keyPoint1 = keyPoint1.add(publicKey.multiply(r));
        }

        BigInteger c = params.hash(base, point1, point2, publicKey, basePoint1, keyPoint1, basePoint2, keyPoint2);

        final BigInteger c1, c2, s1, s2;
        if (isFirst) {
            c1 = c.subtract(r).mod(params.getGroupSize());
            c2 = r;
            s1 = e1.subtract(secretKey.multiply(c1)).mod(params.getGroupSize());
            s2 = e2;
        } else {
            c1 = r;
            c2 = c.subtract(r).mod(params.getGroupSize());
            s1 = e1;
            s2 = e2.subtract(secretKey.multiply(c2)).mod(params.getGroupSize());
        }

        return new OneOfTwoDlogProof(params, c1, c2, s1, s2);
    }

    public static OneOfTwoDlogProof serialReadIn(InputStream inStream, EncryptionParams params) throws IOException {
        BigInteger c1 = SerialHelpers.readBigInteger(inStream);
        BigInteger c2 = SerialHelpers.readBigInteger(inStream);
        BigInteger s1 = SerialHelpers.readBigInteger(inStream);
        BigInteger s2 = SerialHelpers.readBigInteger(inStream);

        return new OneOfTwoDlogProof(params, c1, c2, s1, s2);
    }

    public boolean verify(ECPoint base, ECPoint point1, ECPoint point2, ECPoint publicKey) {
        ECPoint basePoint1 = base.multiply(m_s1).add(point1.multiply(m_c1));
        ECPoint keyPoint1 = m_params.getGenerator().multiply(m_s1).add(publicKey.multiply(m_c1));
        ECPoint basePoint2 = base.multiply(m_s2).add(point2.multiply(m_c2));
        ECPoint keyPoint2 = m_params.getGenerator().multiply(m_s2).add(publicKey.multiply(m_c2));

        BigInteger c = m_params.hash(base, point1, point2, publicKey, basePoint1, keyPoint1, basePoint2, keyPoint2);

        return c.equals(m_c1.add(m_c2).mod(m_params.getGroupSize()));
    }

    @Override
    public void serialWriteOut(OutputStream outStream, boolean compressPoints) throws IOException {
        SerialHelpers.writeBigInteger(outStream, m_c1);
        SerialHelpers.writeBigInteger(outStream, m_c2);
        SerialHelpers.writeBigInteger(outStream, m_s1);
        SerialHelpers.writeBigInteger(outStream, m_s2);
    }

    @Override
    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof OneOfTwoDlogProof)) return false;

        OneOfTwoDlogProof pf = (OneOfTwoDlogProof) o;
        return Objects.equals(m_c1, pf.m_c1) && Objects.equals(m_c2, pf.m_c2) && Objects.equals(m_s1, pf.m_s1)
                && Objects.equals(m_s2, pf.m_s2);
    }

    @Override
    public int hashCode() {
        return Objects.hash(m_c1, m_c2, m_s1, m_s2);
    }
}
