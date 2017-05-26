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

import org.bouncycastle.math.ec.ECPoint;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import com.google.common.collect.ImmutableList;

import solidus.state.pvorm.PlaintextCircuitOram;
import solidus.util.CryptoConstants;
import solidus.util.EncryptionParams;

import test.util.TestUtils;

import java.util.Collection;
import java.util.List;
import java.util.Random;

/**
 * Testing the correctness of {@code PlaintextOram}
 *
 * @author ethan@cs.cornell.edu
 */
@RunWith(Parameterized.class)
public class PlaintextCircuitOramTest {
    @Parameters
    public static Collection<Object[]> oramConfigurations() {
        return ImmutableList.copyOf(new Object[][] {
                // Tree depth, bucket size, stash size, number of accounts
                { 1, 1, 1, 1 }, { 4, 1, 2, 2 }, { 4, 2, 4, 4 }, { 4, 2, 10, 16 }, { 5, 4, 10, 32 } });
    }

    private final EncryptionParams m_params;
    private final List<ECPoint> m_accountKeys;
    private final PlaintextCircuitOram m_oram;

    public PlaintextCircuitOramTest(int treeDepth, int bucketSize, int stashSize, int numAccounts) {
        Random rand = new Random(TestUtils.RANDOM_SEED);
        m_params = EncryptionParams.newTestParams(rand, CryptoConstants.CURVE, CryptoConstants.DIGEST);

        m_oram = new PlaintextCircuitOram(treeDepth, bucketSize, stashSize, rand);
        ImmutableList.Builder<ECPoint> keysBuilder = new ImmutableList.Builder<>();
        for (int i = 0; i < numAccounts; i++) {
            ECPoint key = m_params.getGenerator().multiply(m_params.getRandomIndex()).normalize();
            keysBuilder.add(key);
            m_oram.insert(key, i);
        }

        m_accountKeys = keysBuilder.build();
    }

    @Test
    public void testOram() {
        for (int i = 0; i < m_accountKeys.size(); i++) {
            Assert.assertEquals(i, m_oram.getBalance(m_accountKeys.get(i)));
        }

        for (ECPoint key : m_accountKeys) {
            m_oram.update(key, m_accountKeys.size());
        }

        for (int i = 0; i < m_accountKeys.size(); i++) {
            Assert.assertEquals(i + m_accountKeys.size(), m_oram.getBalance(m_accountKeys.get(i)));
        }
    }
}
