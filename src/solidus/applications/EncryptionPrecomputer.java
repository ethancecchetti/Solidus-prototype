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

package solidus.applications;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Random;

import org.bouncycastle.crypto.ec.ECPair;
import org.bouncycastle.math.ec.ECPoint;

import com.google.common.base.Stopwatch;

import solidus.io.SerialHelpers;
import solidus.util.CryptoConstants;
import solidus.util.EncryptionParams;
import solidus.util.Encryptor;

public class EncryptionPrecomputer {
    public static void main(String[] args) throws IOException {
        Path outputFile = Paths.get(args[0]);
        BigInteger secretKey = new BigInteger(args[1]);
        int numEncryptions = Integer.parseInt(args[2]);
        int threadCount = (args.length < 4 ? 0 : Integer.parseInt(args[3]));

        EncryptionParams params = new EncryptionParams.Builder(new Random(1), CryptoConstants.CURVE,
                CryptoConstants.DIGEST).normalizePoints().setEncryptorThreads(threadCount).forTesting().build();

        System.out.println(secretKey);
        ECPoint publicKey = params.getGenerator().multiply(secretKey).normalize();
        Encryptor encryptor = params.getEncryptor(publicKey);

        try (OutputStream out = new BufferedOutputStream(Files.newOutputStream(outputFile, StandardOpenOption.WRITE,
                StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.CREATE))) {
            SerialHelpers.writeString(out, params.getCurveName());
            SerialHelpers.writeECPoint(out, publicKey, false);

            Stopwatch watch = Stopwatch.createStarted();
            for (int i = 0; i < numEncryptions; i++) {
                ECPair encryption = encryptor.encryptZero();
                SerialHelpers.writeECPair(out, encryption, false);
            }
            watch.stop();
            System.out.println("Time taken: " + watch);
        }
    }
}
