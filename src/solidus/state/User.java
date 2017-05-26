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

import org.bouncycastle.math.ec.ECPoint;

import solidus.trans.TransactionRequest;
import solidus.util.EncryptionParams;

import java.math.BigInteger;

/**
 * Created by fanz on 11/6/16.
 */
public class User {
    private final EncryptionParams m_params;
    private final ECPoint m_hostBankPublicKey;

    private final BigInteger m_secretKey;
    private final ECPoint m_accountKey;

    public User(EncryptionParams params, ECPoint hostBankPublicKey, BigInteger secretKey) {
        m_params = params;
        m_hostBankPublicKey = hostBankPublicKey;

        m_secretKey = secretKey;
        m_accountKey = params.getGenerator().multiply(secretKey).normalize();
    }

    public TransactionRequest buildTransactionRequest(ECPoint destBank, ECPoint destAccount, long value) {
        return TransactionRequest.buildRequest(m_params, m_hostBankPublicKey, destBank, destAccount, value,
                m_secretKey);
    }

    public ECPoint getAccountKey() {
        return m_accountKey;
    }

}
