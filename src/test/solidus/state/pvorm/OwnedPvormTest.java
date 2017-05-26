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

package test.solidus.state.pvorm;

import java.math.BigInteger;
import java.util.Map;
import java.util.Random;

import com.google.common.collect.ImmutableMap;

import org.bouncycastle.math.ec.ECPoint;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import solidus.state.pvorm.EncryptedPvorm;
import solidus.state.pvorm.OwnedPvorm;
import solidus.state.pvorm.PvormUpdate;
import solidus.util.CryptoConstants;
import solidus.util.EncryptionParams;
import solidus.util.Encryptor;

import test.util.TestUtils;

public class OwnedPvormTest {
    private static final int MAX_BALANCE = (1 << 8) - 1;
    private static final int MAX_DISCRETE_LOG_BITS = 30;
    private static final EncryptionParams PARAMS = new EncryptionParams.Builder(new Random(TestUtils.RANDOM_SEED),
            CryptoConstants.CURVE, CryptoConstants.DIGEST).setMaxDiscreteLog(MAX_BALANCE)
                    .setMaxDiscreteLogBits(MAX_DISCRETE_LOG_BITS).forTesting().build();

    private static final int BUCKET_SIZE = 2;
    private static final int STASH_SIZE = 5;

    private static Map<ECPoint, Long> m_accountBalances;

    private static OwnedPvorm m_pvorm1;
    private static OwnedPvorm m_pvorm2;

    private static EncryptedPvorm m_pvorm1Duplicate;

    @BeforeClass
    public static void setup() {
        ECPoint gen = PARAMS.getGenerator();
        m_accountBalances = new ImmutableMap.Builder<ECPoint, Long>()
                .put(gen.multiply(BigInteger.valueOf(0x48058cc00232642eL)), 0x83L)
                .put(gen.multiply(BigInteger.valueOf(0x45acedf4106b9d31L)), 0x92L)
                .put(gen.multiply(BigInteger.valueOf(0x3d462f7129165283L)), 0x53L)
                .put(gen.multiply(BigInteger.valueOf(0xbabc829377da672fL)), 0x0bL)
                .put(gen.multiply(BigInteger.valueOf(0x5b2fdfcda608bf98L)), 0x54L)
                .put(gen.multiply(BigInteger.valueOf(0x195cfd7823b69249L)), 0x8bL)
                .put(gen.multiply(BigInteger.valueOf(0xa603c9946988d15bL)), 0xd0L).build();

        int treeDepth = Integer.SIZE - Integer.numberOfLeadingZeros(m_accountBalances.size());

        BigInteger secretKey1 = new BigInteger("0db45fc6c510398fdc5dbc81eb7f132ce3b6312f5feb894f3debe14bea6e6e36", 16);
        BigInteger secretKey2 = new BigInteger("8de8388c1b42e0211d52d0fed21aa03aebdb29425a2983c5c18c7e29f21cdb79", 16);
        OwnedPvorm.Builder pvorm1Builder = new OwnedPvorm.Builder(PARAMS, secretKey1, treeDepth, BUCKET_SIZE,
                STASH_SIZE);
        OwnedPvorm.Builder pvorm2Builder = new OwnedPvorm.Builder(PARAMS, secretKey2, treeDepth, BUCKET_SIZE,
                STASH_SIZE);
        for (Map.Entry<ECPoint, Long> entry : m_accountBalances.entrySet()) {
            pvorm1Builder.insert(entry.getKey(), entry.getValue());
            pvorm2Builder.insert(entry.getKey(), entry.getValue());
        }

        m_pvorm1 = pvorm1Builder.build();
        m_pvorm2 = pvorm2Builder.build();
        m_pvorm1Duplicate = m_pvorm1.getEncryptedPvorm().duplicate();
    }

    @Test
    public void testBalances() {
        Assert.assertEquals(m_accountBalances,
                m_pvorm1.getEncryptedPvorm().decryptAll(PARAMS, m_pvorm1.getSecretKey()));
        Assert.assertEquals(m_accountBalances,
                m_pvorm2.getEncryptedPvorm().decryptAll(PARAMS, m_pvorm2.getSecretKey()));
        Assert.assertEquals(m_accountBalances, m_pvorm1Duplicate.decryptAll(PARAMS, m_pvorm1.getSecretKey()));
    }

    @Test
    public void testSerializeEncryptedPvorms() {
        TestUtils.testSerialization(m_pvorm1.getEncryptedPvorm(), EncryptedPvorm::serialReadIn, PARAMS);
        TestUtils.testSerialization(m_pvorm2.getEncryptedPvorm(), EncryptedPvorm::serialReadIn, PARAMS);
        TestUtils.testSerialization(m_pvorm1Duplicate, EncryptedPvorm::serialReadIn, PARAMS);
    }

    @Test
    public void testUpdates() {
        Encryptor encryptor = PARAMS.getEncryptor(m_pvorm1.getPublicKey());

        // Update all balances to 0 and make sure the updates all go through.
        for (ECPoint key : m_accountBalances.keySet()) {
            long balance = m_accountBalances.get(key).longValue();
            PvormUpdate update = m_pvorm1.update(encryptor.encryptPoint(key), encryptor.encryptBalance(-balance), true);

            Assert.assertEquals(0, m_pvorm1.getBalance(key));

            TestUtils.testSerialization(update, PvormUpdate::serialReadIn, PARAMS);
            Assert.assertTrue(m_pvorm1Duplicate.verifyUpdate(update));
            Assert.assertFalse(m_pvorm2.getEncryptedPvorm().verifyUpdate(update));

            // Make sure the balance in the duplicate pvorm only changes when we
            // apply the update.
            Assert.assertEquals(balance,
                    m_pvorm1Duplicate.decryptAll(PARAMS, m_pvorm1.getSecretKey()).get(key).longValue());
            m_pvorm1Duplicate.applyLastVerifiedUpdate();
            Assert.assertEquals(0, m_pvorm1Duplicate.decryptAll(PARAMS, m_pvorm1.getSecretKey()).get(key).longValue());

            // Make sure encrypted side of pvorms stay in sync
            Assert.assertEquals(m_pvorm1.getEncryptedPvorm(), m_pvorm1Duplicate);
        }

        // Make sure everything is zeros
        ImmutableMap.Builder<ECPoint, Long> zeroBalanceMapBuilder = new ImmutableMap.Builder<>();
        for (ECPoint key : m_accountBalances.keySet())
            zeroBalanceMapBuilder.put(key, 0L);
        Map<ECPoint, Long> zeroBalanceMap = zeroBalanceMapBuilder.build();

        Assert.assertEquals(zeroBalanceMap, m_pvorm1.getEncryptedPvorm().decryptAll(PARAMS, m_pvorm1.getSecretKey()));
        Assert.assertEquals(zeroBalanceMap, m_pvorm1Duplicate.decryptAll(PARAMS, m_pvorm1.getSecretKey()));

        // Make sure balances didn't change in the other pvorm
        Assert.assertEquals(m_accountBalances,
                m_pvorm2.getEncryptedPvorm().decryptAll(PARAMS, m_pvorm2.getSecretKey()));

        // Update everything back to the original state so we don't mess up
        // other tests
        for (ECPoint key : m_accountBalances.keySet()) {
            long balance = m_accountBalances.get(key).longValue();
            PvormUpdate update = m_pvorm1.update(encryptor.encryptPoint(key), encryptor.encryptBalance(balance), true);

            TestUtils.testSerialization(update, PvormUpdate::serialReadIn, PARAMS);
            Assert.assertTrue(m_pvorm1Duplicate.verifyUpdate(update));
            m_pvorm1Duplicate.applyLastVerifiedUpdate();
        }
        Assert.assertEquals(m_accountBalances,
                m_pvorm1.getEncryptedPvorm().decryptAll(PARAMS, m_pvorm1.getSecretKey()));
        Assert.assertEquals(m_accountBalances, m_pvorm1Duplicate.decryptAll(PARAMS, m_pvorm1.getSecretKey()));
        Assert.assertEquals(m_pvorm1.getEncryptedPvorm(), m_pvorm1Duplicate);
    }
}
