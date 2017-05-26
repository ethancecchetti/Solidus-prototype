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

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Random;
import java.util.function.Supplier;

import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.prng.X931SecureRandomBuilder;
import org.bouncycastle.jcajce.provider.digest.SHA256;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;

public class CryptoConstants {
    /**
     * The name of the elliptic curve to use for all crypto operations.
     * Currently secp256k1.
     */
    public static final String CURVE_NAME = "secp256k1";

    /**
     * A constructor for the hash function to use. Currently using SHA256.
     */
    public static final Supplier<MessageDigest> DIGEST = SHA256.Digest::new;

    /**
     * The elliptic curve spec to use, constructed by a lookup using
     * {@link #CURVE_NAME}.
     */
    public static final ECNamedCurveParameterSpec CURVE = ECNamedCurveTable.getParameterSpec(CURVE_NAME);

    /**
     * Builds a new pseudo-random generator to be used for all purposes within
     * the system. The PRNG is seeded using {@code java.security.SecureRandom}'s
     * {@code generateSeed} method.
     *
     * @return a new pseudo-random generator that has been securely seeded with
     *         true randomness.
     *
     * @see java.security.SecureRandom
     */
    public static Random buildPrng() {
        return new X931SecureRandomBuilder().build(new AESFastEngine(),
                new KeyParameter(new SecureRandom().generateSeed(32)), false);
    }

    // This is a static constants class. There is no reason to instantiate it.
    private CryptoConstants() {}
}
