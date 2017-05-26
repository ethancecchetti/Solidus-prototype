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

package test.solidus.trans;

import java.math.BigInteger;
import java.util.List;
import java.util.Random;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import org.bouncycastle.math.ec.ECPoint;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.experimental.theories.suppliers.TestedOn;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;

import com.google.common.collect.ImmutableList;

import solidus.state.LocalBank;
import solidus.state.User;
import solidus.state.pvorm.EncryptedPvorm;
import solidus.trans.Transaction;
import solidus.trans.TransactionHeader;
import solidus.trans.TransactionRequest;
import solidus.util.CryptoConstants;
import solidus.util.EncryptionParams;
import solidus.util.Utils;

import test.util.TestUtils;

@RunWith(Theories.class)
public class TransactionTest {
    private static final int MAX_BALANCE = (1 << 8) - 1;
    private static final int MAX_DISCRETE_LOG_BITS = 30;

    private static final int TREE_DEPTH = 3;
    private static final int BUCKET_SIZE = 2;
    private static final int STASH_SIZE = 5;

    private static final int STARTING_BALANCE = 10;

    private static final int THREAD_COUNT = 4;

    private static EncryptionParams m_params;

    private static BigInteger m_bank1SecretDecKey;
    private static BigInteger m_bank2SecretDecKey;
    private static LocalBank m_bank1;
    private static LocalBank m_bank2;

    private static User m_testUser1;
    private static User m_testUser2;

    @BeforeClass
    public static void setup() {
        m_params = new EncryptionParams.Builder(new Random(TestUtils.RANDOM_SEED), CryptoConstants.CURVE,
                CryptoConstants.DIGEST).setMaxDiscreteLog(MAX_BALANCE).setMaxDiscreteLogBits(MAX_DISCRETE_LOG_BITS)
                        .forTesting().build();

        m_bank1SecretDecKey = new BigInteger("537b5be33b45d317423cb4f1a34809b96145899cc993e0245fdd1b6a8d5d61ad", 16);
        m_bank2SecretDecKey = new BigInteger("7681dbe3269f3baf9e921f28735329890bf866d4c3935b3fe0b2d9c160113616", 16);

        ECPoint bank1PublicEncKey = m_params.getGenerator().multiply(m_bank1SecretDecKey).normalize();
        ECPoint bank2PublicEncKey = m_params.getGenerator().multiply(m_bank2SecretDecKey).normalize();

        List<User> bank1Users = ImmutableList.of(
                new User(m_params, bank1PublicEncKey, BigInteger.valueOf(0x2481b437a2e7796bL)),
                new User(m_params, bank1PublicEncKey, BigInteger.valueOf(0xb3082fce39a574c2L)),
                new User(m_params, bank1PublicEncKey, BigInteger.valueOf(0xa9b15da351528a3aL)),
                new User(m_params, bank1PublicEncKey, BigInteger.valueOf(0x221af00d803b9306L)));
        List<User> bank2Users = ImmutableList.of(
                new User(m_params, bank2PublicEncKey, BigInteger.valueOf(0x51b7e49159efc30dL)),
                new User(m_params, bank2PublicEncKey, BigInteger.valueOf(0x226c6d8f7e5f4165L)),
                new User(m_params, bank2PublicEncKey, BigInteger.valueOf(0x2cbb8c3303e3360cL)),
                new User(m_params, bank2PublicEncKey, BigInteger.valueOf(0x4c461852897a0503L)));
        List<Long> startingBalances = Utils.buildRepeatList(Long.valueOf(STARTING_BALANCE), bank1Users.size());

        m_testUser1 = bank1Users.get(0);
        m_testUser2 = bank2Users.get(0);

        m_bank1 = new LocalBank(m_params, TREE_DEPTH, BUCKET_SIZE, STASH_SIZE, m_bank1SecretDecKey,
                new BigInteger("79a44357e85b276035d886b7ec68f34115510578bd3d796c06a035ce3206c7e8", 16), bank1Users,
                startingBalances);
        m_bank2 = new LocalBank(m_params, TREE_DEPTH, BUCKET_SIZE, STASH_SIZE, m_bank2SecretDecKey,
                new BigInteger("5ac742296ceb03cbd20097c84923e5b52bce0409629a3be71108aac60203b0ab", 16), bank2Users,
                startingBalances);
    }

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @Test
    public void testRequest() {
        TransactionRequest req = m_testUser1.buildTransactionRequest(m_bank2.getPublicEncryptionKey(),
                m_testUser2.getAccountKey(), STARTING_BALANCE);

        Assert.assertEquals(m_bank1.getPublicEncryptionKey(), req.getSourceBankKey());
        Assert.assertEquals(m_bank2.getPublicEncryptionKey(), req.getDestBankKey());
        Assert.assertEquals(m_testUser1.getAccountKey(),
                m_params.getDecryptor(m_bank1SecretDecKey).decryptPoint(req.getSourceAccountCipher()));
        Assert.assertEquals(m_testUser2.getAccountKey(),
                m_params.getDecryptor(m_bank2SecretDecKey).decryptPoint(req.getDestAccountCipher()));
        Assert.assertTrue(req.verifySignature());

        TestUtils.testSerialization(req, TransactionRequest::serialReadIn, m_params);
    }

    @Theory
    public void testValidHeaderGeneration(@TestedOn(ints = { 0, STARTING_BALANCE - 1, STARTING_BALANCE }) int value,
            boolean threaded) throws InterruptedException {
        ExecutorService executor = (threaded ? Executors.newFixedThreadPool(THREAD_COUNT) : null);

        TransactionRequest req = m_testUser1.buildTransactionRequest(m_bank2.getPublicEncryptionKey(),
                m_testUser2.getAccountKey(), value);
        TransactionHeader header = m_bank1.generateHeader(req, executor);

        Assert.assertEquals(req, header.getRequest());
        Assert.assertTrue(header.getValueRangeProof().verify(req.getValueCipher(), m_bank1.getPublicEncryptionKey()));
        Assert.assertTrue(header.getProofOfRerandomize().verify(req.getValueCipher(),
                header.getSenderRerandomizedValue(), m_bank1.getPublicEncryptionKey()));
        Assert.assertTrue(header.getProofOfReencryption().verify(header.getSenderRerandomizedValue(),
                header.getReceiverValue(), m_bank1.getPublicEncryptionKey(), m_bank2.getPublicEncryptionKey()));
        Assert.assertTrue(header.verifyProofs());

        TestUtils.testSerialization(header, TransactionHeader::serialReadIn, m_params);

        if (threaded) {
            executor.shutdown();
            Assert.assertTrue(executor.awaitTermination(1, TimeUnit.SECONDS));
        }
    }

    @Theory
    public void testBadTransactionValue(@TestedOn(ints = { -1, STARTING_BALANCE + 1 }) int value) {
        thrown.expect(IllegalArgumentException.class);

        TransactionRequest req = m_testUser1.buildTransactionRequest(m_bank2.getPublicEncryptionKey(),
                m_testUser2.getAccountKey(), value);
        m_bank1.generateHeader(req, null);
    }

    @Test
    public void testBadSourceAccount() {
        thrown.expect(IllegalArgumentException.class);

        TransactionRequest req = m_testUser1.buildTransactionRequest(m_bank2.getPublicEncryptionKey(),
                m_testUser2.getAccountKey(), STARTING_BALANCE);
        m_bank2.generateHeader(req, null);
    }

    @Theory
    public void testTransaction(@TestedOn(ints = { 0, 1, STARTING_BALANCE }) int value, boolean threaded)
            throws InterruptedException {
        ExecutorService executor = (threaded ? Executors.newFixedThreadPool(THREAD_COUNT) : null);

        EncryptedPvorm snapshotBank1 = m_bank1.getEncryptedPvorm();
        EncryptedPvorm snapshotBank2 = m_bank2.getEncryptedPvorm();

        {
            TransactionRequest req = m_testUser1.buildTransactionRequest(m_bank2.getPublicEncryptionKey(),
                    m_testUser2.getAccountKey(), value);
            TransactionHeader header = m_bank1.generateHeader(req, executor);
            Transaction.SenderInfo senderInfo = m_bank1.sendTransaction(header, executor);
            Transaction.ReceiverInfo receiverInfo = m_bank2.receiveTransaction(header, executor);
            Transaction trans = new Transaction(senderInfo, receiverInfo);

            Assert.assertTrue(snapshotBank1.verifyUpdate(trans.getSenderUpdate(), executor));
            Assert.assertTrue(snapshotBank2.verifyUpdate(trans.getReceiverUpdate(), executor));
            Assert.assertTrue(trans.verifySenderSignature(m_bank1.getPublicSigKey()));
            Assert.assertTrue(trans.verifyReceiverSignature(m_bank2.getPublicSigKey()));

            TestUtils.testSerialization(trans, Transaction::serialReadIn, m_params);

            snapshotBank1.applyLastVerifiedUpdate();
            snapshotBank2.applyLastVerifiedUpdate();
        }

        // Send the money bank so nothing else gets messed up.
        {
            TransactionRequest req = m_testUser2.buildTransactionRequest(m_bank1.getPublicEncryptionKey(),
                    m_testUser1.getAccountKey(), value);
            TransactionHeader header = m_bank2.generateHeader(req, executor);
            Transaction.SenderInfo senderInfo = m_bank2.sendTransaction(header, executor);
            Transaction.ReceiverInfo receiverInfo = m_bank1.receiveTransaction(header, executor);
            Transaction trans = new Transaction(senderInfo, receiverInfo);

            Assert.assertTrue(snapshotBank1.verifyUpdate(trans.getReceiverUpdate(), executor));
            Assert.assertTrue(snapshotBank2.verifyUpdate(trans.getSenderUpdate(), executor));
            Assert.assertTrue(trans.verifyReceiverSignature(m_bank1.getPublicSigKey()));
            Assert.assertTrue(trans.verifySenderSignature(m_bank2.getPublicSigKey()));

            TestUtils.testSerialization(trans, Transaction::serialReadIn, m_params);

            snapshotBank1.applyLastVerifiedUpdate();
            snapshotBank2.applyLastVerifiedUpdate();
        }

        if (threaded) {
            executor.shutdown();
            Assert.assertTrue(executor.awaitTermination(1, TimeUnit.SECONDS));
        }
    }
}
