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

import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;

import com.google.common.collect.ImmutableList;

/**
 * This is a static utility class that provides a few convenience methods. All
 * of these are slightly clunky operations to inline that are used in at least a
 * few places.
 *
 * This class cannot be instantiated.
 *
 * @author ethan@cs.cornell.edu
 */
public class Utils {
    /**
     * Builds an immutable List consisting of the specified value the specified
     * number of times.
     *
     * @param <T> The type of the list to create.
     * @param value The value to populate every element of the list with.
     * @param length The number of elements in the list. If {@code length < 0},
     *            the list will be empty.
     * @return A new immutable list with {@code value} repeated {@code length}
     *         times.
     */
    public static <T> List<T> buildRepeatList(T value, int length) {
        ImmutableList.Builder<T> builder = new ImmutableList.Builder<>();
        for (int i = 0; i < length; i++)
            builder.add(value);
        return builder.build();
    }

    /**
     * A convenience method for getting values out of <a target="_blank" href=
     * "https://docs.oracle.com/javase/8/docs/api/java/util/concurrent/Future.html">
     * Future</a> objects while using the JDK Streams API. The Java Streams API
     * does not handle checked exceptions and <a target="_blank" href=
     * "https://docs.oracle.com/javase/8/docs/api/java/util/concurrent/Future.html#get--">
     * Future.get()</a> throws checked exceptions, so this method simply catches
     * those exceptions and wraps them in an unchecked {@code
     * java.lang.RuntimeException}. If no exception is thrown, it returns the
     * value in the future.
     *
     * @param <T> The type of the value inside the future.
     * @param f The future to get the value inside of.
     * @return The value stored in {@code f}.
     * @throws RuntimeException If {@code f.get()} threw an {@code
     *         java.lang.InterruptedException} or {@code
     *         java.util.concurrent.ExecutionException}.
     */
    public static <T> T getFuture(Future<T> f) {
        try {
            return f.get();
        } catch (InterruptedException | ExecutionException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Submits the specified job to the specified thread pool if the executor is
     * not {@code null}, otherwise runs the job in the current thread.
     *
     * @param <T> The return type of the job to execute.
     * @param job The job to execute.
     * @param executor The thread pool in which to run the job or {@code null}
     *            if the job should be run in the current thread.
     * @return A Future representing the result of the computation. The
     *         computation will already be complete if {@code executor == null}.
     * @throws RuntimeException If executing the job locally threw an exception.
     */
    public static <T> Future<T> submitJob(Callable<T> job, ExecutorService executor) {
        if (executor == null) {
            try {
                return CompletableFuture.completedFuture(job.call());
            } catch (Exception e) {
                // This means something went wrong executing the job,
                // so we should blow up here.
                throw new RuntimeException(e);
            }
        } else {
            return executor.submit(job);
        }
    }

    // Ensure that this class cannot be instantiated.
    private Utils() {}
}
