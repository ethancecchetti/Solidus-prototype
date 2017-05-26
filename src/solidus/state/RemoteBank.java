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

package solidus.state;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.List;

import org.bouncycastle.math.ec.ECPoint;

import com.google.common.collect.ImmutableList;

import solidus.io.SerialHelpers;
import solidus.io.SerialWriter;
import solidus.state.pvorm.EncryptedPvorm;
import solidus.util.EncryptionParams;

public class RemoteBank implements SerialWriter {
    private final ECPoint m_encryptionKey;
    private final ECPoint m_sigVerKey;
    private final List<ECPoint> m_userKeys;
    private final EncryptedPvorm m_pvorm;

    public RemoteBank(ECPoint encryptionKey, ECPoint sigVerKey, List<ECPoint> userKeys, EncryptedPvorm pvorm) {
        m_encryptionKey = encryptionKey;
        m_sigVerKey = sigVerKey;
        m_userKeys = ImmutableList.copyOf(userKeys);
        m_pvorm = pvorm;
    }

    public ECPoint getEncryptionKey() {
        return m_encryptionKey;
    }

    public ECPoint getSigVerKey() {
        return m_sigVerKey;
    }

    public List<ECPoint> getUserKeys() {
        return m_userKeys;
    }

    public EncryptedPvorm getPvorm() {
        return m_pvorm;
    }

    public static RemoteBank serialReadIn(InputStream inStream, EncryptionParams params) throws IOException {
        ECPoint encryptionKey = SerialHelpers.readECPoint(inStream, params);
        ECPoint sigVerKey = SerialHelpers.readECPoint(inStream, params);
        int numberOfUsers = SerialHelpers.readInt(inStream);
        ImmutableList.Builder<ECPoint> userKeysBuilder = new ImmutableList.Builder<>();
        for (int i = 0; i < numberOfUsers; i++) {
            userKeysBuilder.add(SerialHelpers.readECPoint(inStream, params));
        }
        EncryptedPvorm pvorm = EncryptedPvorm.serialReadIn(inStream, params);

        return new RemoteBank(encryptionKey, sigVerKey, userKeysBuilder.build(), pvorm);
    }

    @Override
    public void serialWriteOut(OutputStream outStream, boolean compressPoints) throws IOException {
        SerialHelpers.writeECPoint(outStream, m_encryptionKey, compressPoints);
        SerialHelpers.writeECPoint(outStream, m_sigVerKey, compressPoints);
        SerialHelpers.writeInt(outStream, m_userKeys.size());
        for (ECPoint key : m_userKeys)
            SerialHelpers.writeECPoint(outStream, key, compressPoints);
        m_pvorm.serialWriteOut(outStream, compressPoints);
    }
}
