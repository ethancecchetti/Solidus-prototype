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

import org.bouncycastle.math.ec.ECPoint;

import solidus.io.SerialHelpers;
import solidus.io.SerialWriter;
import solidus.util.EncryptionParams;

public class SchnorrSignature implements Signature {
    public static SchnorrSignature sign(EncryptionParams params, BigInteger signingKey, SerialWriter firstMessagePart,
            SerialWriter... messageParts) {
        byte[][] encodedMessageParts = new byte[messageParts.length + 1][];
        encodedMessageParts[0] = firstMessagePart.toByteArray();
        for (int i = 0; i < messageParts.length; i++) {
            encodedMessageParts[i + 1] = messageParts[i].toByteArray();
        }
        return sign(params, signingKey, encodedMessageParts);
    }

    public static SchnorrSignature sign(EncryptionParams params, BigInteger signingKey, byte[]... messageParts) {
        BigInteger randMult = params.getRandomIndex();
        ECPoint randPoint = params.getGenerator().multiply(randMult);
        BigInteger challenge = params.hashDataAndPoints(messageParts, randPoint);
        BigInteger s = randMult.subtract(signingKey.multiply(challenge)).mod(params.getGroupSize());

        return new SchnorrSignature(params, s, challenge);
    }

    private final EncryptionParams m_params;
    private final BigInteger m_s;
    private final BigInteger m_challenge;

    private SchnorrSignature(EncryptionParams params, BigInteger s, BigInteger challenge) {
        m_params = params;
        m_s = s;
        m_challenge = challenge;
    }

    @Override
    public boolean verify(ECPoint verificationKey, byte[]... messageParts) {
        ECPoint challengePoint = m_params.getGenerator().multiply(m_s).add(verificationKey.multiply(m_challenge));
        return m_params.hashDataAndPoints(messageParts, challengePoint).equals(m_challenge);
    }

    @Override
    public void serialWriteOut(OutputStream outStream, boolean compressPoints) throws IOException {
        SerialHelpers.writeBigInteger(outStream, m_s);
        SerialHelpers.writeBigInteger(outStream, m_challenge);
    }

    public static SchnorrSignature serialReadIn(InputStream inStream, EncryptionParams params) throws IOException {
        BigInteger s = SerialHelpers.readBigInteger(inStream);
        BigInteger challenge = SerialHelpers.readBigInteger(inStream);

        return new SchnorrSignature(params, s, challenge);
    }

    @Override
    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof SchnorrSignature)) return false;

        SchnorrSignature sig = (SchnorrSignature) o;
        return Objects.equals(m_s, sig.m_s) && Objects.equals(m_challenge, sig.m_challenge);
    }

    @Override
    public int hashCode() {
        return Objects.hash(m_s, m_challenge);
    }
}
