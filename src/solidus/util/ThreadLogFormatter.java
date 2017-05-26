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

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.logging.Formatter;
import java.util.logging.LogRecord;

public class ThreadLogFormatter extends Formatter {
    // This needs to be ThreadLocal since SimpleDateFormat is not thread safe.
    private static final ThreadLocal<DateFormat> DATE_FORMAT = ThreadLocal
            .withInitial(() -> new SimpleDateFormat("hh:mm:ss.SSS"));

    @Override
    public String format(LogRecord record) {
        String lastClassName = record.getSourceClassName().substring(record.getSourceClassName().lastIndexOf('.') + 1);
        return String.format("[%-7s] [%s] [%s %-2d] %s <%s.%s>\n", record.getLevel(),
                DATE_FORMAT.get().format(new Date(record.getMillis())), record.getLoggerName(), record.getThreadID(),
                formatMessage(record), lastClassName, record.getSourceMethodName());
    }
}
