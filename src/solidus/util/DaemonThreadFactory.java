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

import java.util.concurrent.ThreadFactory;

public class DaemonThreadFactory implements ThreadFactory {
    private static String m_namePrefix;

    private int m_counter;

    public DaemonThreadFactory(String namePrefix) {
        m_namePrefix = namePrefix + "-";
        m_counter = 0;
    }

    @Override
    public Thread newThread(Runnable r) {
        m_counter++;
        String name = m_namePrefix + m_counter;
        Thread t = new Thread(r, name);
        t.setDaemon(true);
        return t;
    }
}
