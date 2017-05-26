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

package solidus.util;

import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.bouncycastle.crypto.ec.ECPair;
import org.bouncycastle.math.ec.ECPoint;

/**
 * A simple extention of {@link solidus.util.AbstractEncryptor
 * AbstractEncryptor} to generate El Gamal encryptions while computing
 * randomization factors online or in the background. The Encryptor will use a
 * number of threads specified at construction to compute randomzation factors
 * in the background and only truly compute the randomizations online if there
 * are no background-computed factors available. If the Encryptor is
 * instantiated with no threads, this will always be the case.
 *
 * @see solidus.util.Encryptor
 * @author ethan@cs.cornell.edu
 */
public class OnlineEncryptor extends AbstractEncryptor {
    private final BlockingQueue<ECPair> m_encryptionQueue;

    /**
     * Constructs a new encryptor.
     *
     * @param params configuration parameters specifying the elliptic curve
     *            group and randomization source to use for encryption.
     * @param publicKey the public key to encrypt under.
     * @param normalize whether or not to normalize points for fast
     *            serialization.
     * @param workerThreads the number of worker threads to spawn to compute
     *            randomization factors in the background. No threads will be
     *            used unless {@code workerThreads > 0}.
     * @param queueSize the maximum number of randomization factors to be stored
     *            before using any. If this many are awaiting use, background
     *            threads will hang until some randomization factors get used.
     */
    public OnlineEncryptor(EncryptionParams params, ECPoint publicKey, boolean normalize, int workerThreads,
            int queueSize) {
        super(params, publicKey, normalize);

        m_encryptionQueue = new ArrayBlockingQueue<>(queueSize);

        if (workerThreads > 0) {
            ExecutorService service = Executors.newFixedThreadPool(workerThreads,
                    new DaemonThreadFactory("EncryptorBG"));
            for (int i = 0; i < workerThreads; i++) {
                service.execute(() -> {
                    while (true) {
                        _queueEncryption(super.generateZeroEncryption());
                    }
                });
            }
            service.shutdown();
        }
    }

    private void _queueEncryption(ECPair encryption) {
        try {
            m_encryptionQueue.put(encryption);
        } catch (InterruptedException e) {
            throw new RuntimeException("Interrupted attempting to queue encryption", e);
        }
    }

    /**
     * This will attempt to pull a zero-encryption from the queue of
     * background-computed randomization factors and will use that if one
     * exists. If none exist, it will compute a new randomization factor online
     * in the current thread and use that. This methodology uses background
     * computation when possible but does not interrupt computation when no
     * randomization factors are available.
     *
     * @return a fresh El Gamal encryption of the group identity.
     * @see solidus.util.Encryptor#encryptZero
     */
    @Override
    public ECPair encryptZero() {
        // Attempt to pull an encryption out of the queue, but don't block
        // waiting for one.
        // If the queue is empty, we'll generate one in this thread to avoid
        // bottlenecking on the background thread.
        // This also avoids the need to special case for when there is no
        // background thread.
        ECPair encryption = m_encryptionQueue.poll();
        if (encryption == null) {
            encryption = super.generateZeroEncryption();
        }
        return encryption;
    }
}
