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

import java.io.BufferedInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Random;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.bouncycastle.crypto.ec.ECPair;
import org.bouncycastle.math.ec.ECPoint;

import com.google.common.base.Stopwatch;

import solidus.io.SerialHelpers;

/**
 * Creates an Encryptor that reads stored encryptions from a file on disk. If
 * the entire file is read and used, it begins generating encryptions as a
 * default encryptor.
 *
 * The file must first contain the name of the curve used in these params
 * followed by an encoding of the public key and then encodings of El Gamal unit
 * encryptions, with no separators. Encodings cannot be compressed.
 *
 * @see solidus.util.Encryptor
 * @author ethan@cs.cornell.edu
 */
public class FromFileEncryptor extends AbstractEncryptor {
    private final InputStream m_inStream;
    private final BlockingQueue<ECPair> m_encryptionQueue;
    private final int m_workerThreads;

    private boolean m_streamIsOpen;

    /**
     * Constructs a new encryptor that pulls randomization factors from a file
     * until they have all been used. Once the entire file has been used, the
     * encryptor will generate more randomization factors online, as in
     * {@link solidus.util.OnlineEncryptor OnlineEncryptor}.
     *
     * @param params configuration parameters specifying the elliptic curve
     *            group and randomization source to use for encryption.
     * @param publicKey the public key to encrypt under.
     * @param storedEncryptionsPath the path to the file containing stored
     *            encryptions.
     * @param normalize whether or not to normalize points for fast
     *            serialization.
     * @param workerThreads the number of worker threads to spawn to compute
     *            randomization factors once the given file has been entirely
     *            used. If {@code workerThreads > 0}, then a bakcground thread
     *            will be used to pull randomization factors from the file.
     *            Otherwise it will be done inline upon request.
     * @param queueSize the maximum number of randomization factors to be stored
     *            before using any. If this many are awaiting use, background
     *            threads will hang until some randomization factors get used.
     * @throws IllegalArgumentException if the given file contains randomization
     *             factors for the wrong elliptic curve or wrong public key.
     * @throws IOException if the given file cannot be accessed.
     * @see solidus.util.Encryptor
     * @see solidus.util.OnlineEncryptor
     */
    public FromFileEncryptor(EncryptionParams params, ECPoint publicKey, Path storedEncryptionsPath, boolean normalize,
            int workerThreads, int queueSize) throws IOException {
        super(params, publicKey, normalize);

        m_inStream = new BufferedInputStream(Files.newInputStream(storedEncryptionsPath));
        m_encryptionQueue = new ArrayBlockingQueue<>(queueSize);
        m_workerThreads = workerThreads;

        try {
            String curveName = SerialHelpers.readString(m_inStream);
            if (!params.getCurveName().equals(curveName)) {
                throw new IllegalArgumentException(
                        "Encryptions were for the wrong curve. Saved encryptions were for curve [" + curveName
                                + "], but [" + params.getCurveName() + "] was expected");
            }

            ECPoint readPublicKey = SerialHelpers.readECPoint(m_inStream, m_params);
            if (!publicKey.equals(readPublicKey)) {
                throw new IllegalArgumentException("Wrong public key specified for this file.");
            }
        } catch (IOException | RuntimeException e) {
            m_inStream.close();
            throw e;
        }
        m_streamIsOpen = true;

        _startExecutor(Math.min(m_workerThreads, 1), "PrecomputedEncryptionReader", () -> {
            ECPair enc = _readZeroEncryption();
            while (enc != null) {
                _queueEncryption(enc);
                enc = _readZeroEncryption();
            }
        });
    }

    private void _queueEncryption(ECPair encryption) {
        try {
            m_encryptionQueue.put(encryption);
        } catch (InterruptedException e) {
            throw new RuntimeException("Interrupted attempting to queue encryption", e);
        }
    }

    private void _startExecutor(int count, String threadPrefix, Runnable job) {
        if (count < 1) return;

        ExecutorService service = Executors.newFixedThreadPool(count, new DaemonThreadFactory(threadPrefix));
        for (int i = 0; i < count; i++)
            service.execute(job);
        service.shutdown();
    }

    private ECPair _readZeroEncryption() {
        try {
            return SerialHelpers.readECPair(m_inStream, m_params);
        } catch (EOFException e) {
            try {
                m_inStream.close();
            } catch (IOException e2) {
                throw new RuntimeException("Failed to close stream", e2);
            }
            m_streamIsOpen = false;
            _startExecutor(m_workerThreads, "BackgroundEncryptor", () -> {
                while (true)
                    _queueEncryption(super.generateZeroEncryption());
            });

            return null;
        } catch (IOException e) {
            // This failure also is probably recoverable by moving into online
            // mode.
            throw new RuntimeException("Failed to read encoded points", e);
        }
    }

    /**
     * Attempts to read and return a randomization factor from the file or its
     * stored queue if any exist. Otherwise it will compute one inline.
     *
     * @see solidus.util.Encryptor#encryptZero
     */
    @Override
    public ECPair encryptZero() {
        ECPair encryption = null;
        if (m_workerThreads > 0) {
            encryption = m_encryptionQueue.poll();
        } else if (m_streamIsOpen) {
            encryption = _readZeroEncryption();
        }

        if (encryption == null) {
            encryption = super.generateZeroEncryption();
        }
        return encryption;
    }

    /**
     * (FOR TESTING ONLY!) main method for testing only.
     *
     * @param args Command line arguments.
     * @throws IOException If there is a problem accessing the file of stored
     *             encryptions.
     */
    public static void main(String[] args) throws IOException {
        EncryptionParams params = EncryptionParams.newTestParams(new Random(1), CryptoConstants.CURVE,
                CryptoConstants.DIGEST);
        Path storedPath = Paths.get(args[0]);
        BigInteger secretKey = new BigInteger(args[1]);
        int encryptionsToGenerate = Integer.parseInt(args[2]);
        int threadCount = (args.length < 4 ? 0 : Integer.parseInt(args[3]));

        FromFileEncryptor encryptor = new FromFileEncryptor(params, params.getGenerator().multiply(secretKey),
                storedPath, true, threadCount, 10000);

        Stopwatch watch = Stopwatch.createStarted();
        for (int i = 0; i < encryptionsToGenerate; i++) {
            encryptor.encryptZero();
            if ((i + 1) % 10000 == 0) System.out.printf("Acquired %d encryptions\n", i + 1);
        }
        watch.stop();
        System.out.println("Total time: " + watch);
    }
}
