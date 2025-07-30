/*
 * Copyright (C) 2025, THL A29 Limited, a Tencent company. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

package org.openjdk.bench.java.security;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.DigestException;
import java.util.Random;
import java.util.concurrent.TimeUnit;
import org.openjdk.jmh.annotations.*;

@State(Scope.Thread)
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
@Warmup(iterations = 3, time = 2)
@Measurement(iterations = 5, time = 2)
@Fork(value = 2, jvmArgsAppend = {
        "-Xms1024m",
        "-Xmx2048m",
        "--add-exports=java.base/sun.security.provider=ALL-UNNAMED"
})
public class SM3ComparisonBenchmark {

    @Param({"1024", "8192", "65536", "1048576"})
    private int dataSize;

    private byte[] inputData;
    private boolean openSSLAvailable;
    private String implementationType;

    @Setup
    public void setup() throws Exception {
        inputData = new byte[dataSize];
        new Random(0x1234567890ABCDEFL).nextBytes(inputData);

        // Check OpenSSL availability and actual usage
        MessageDigest sm3 = MessageDigest.getInstance("SM3");

        System.out.println("=== Benchmark Setup (Data Size: " + dataSize + ") ===");
        System.out.println("SM3 implementation class: " + sm3.getClass().getName());

        // Check OpenSSL status
        if (sm3.getClass().getName().contains("SM3MessageDigest")) {
            try {
                // Check if OpenSSL is available
                java.lang.reflect.Method isOpenSSLAvailable =
                        sm3.getClass().getMethod("isOpenSSLAvailable");
                openSSLAvailable = (Boolean) isOpenSSLAvailable.invoke(null);

                // Check if current instance is using OpenSSL
                java.lang.reflect.Method isUsingOpenSSL =
                        sm3.getClass().getMethod("isUsingOpenSSL");
                boolean usingOpenSSL = (Boolean) isUsingOpenSSL.invoke(sm3);

                implementationType = usingOpenSSL ? "OpenSSL" : "Pure Java";

                System.out.println("OpenSSL available: " + openSSLAvailable);
                System.out.println("Current implementation: " + implementationType);

            } catch (Exception e) {
                openSSLAvailable = false;
                implementationType = "Unknown";
                System.out.println("Could not determine OpenSSL status: " + e.getMessage());
            }
        } else {
            openSSLAvailable = false;
            implementationType = "Unknown";
        }

        // Output test environment information
        System.out.println("Test environment: " + implementationType + " implementation");
        System.out.println("JMH will measure complete workflow including instance creation");
        System.out.println("Use -prof gc to enable GC profiler and observe garbage collection impact");
        System.out.println("Example: java -jar benchmark.jar SM3ComparisonBenchmark -prof gc");
        System.out.println("================================================");
    }

    // ============ Complete Workflow Tests ============

    /**
     * SM3 complete workflow: create instance + single hash computation
     */
    @Benchmark
    public byte[] sm3CompleteWorkflowSingleHash() throws NoSuchAlgorithmException {
        MessageDigest sm3 = MessageDigest.getInstance("SM3");
        return sm3.digest(inputData);
    }

    /**
     * SM3 complete workflow: create instance + incremental update
     */
    @Benchmark
    public byte[] sm3CompleteWorkflowIncrementalUpdate() throws NoSuchAlgorithmException {
        MessageDigest sm3 = MessageDigest.getInstance("SM3");

        int chunkSize = 1024;
        for (int i = 0; i < dataSize; i += chunkSize) {
            int len = Math.min(chunkSize, dataSize - i);
            sm3.update(inputData, i, len);
        }

        return sm3.digest();
    }

    /**
     * SM3 complete workflow: create instance + multiple small updates
     */
    @Benchmark
    public byte[] sm3CompleteWorkflowMultipleSmallUpdates() throws NoSuchAlgorithmException {
        MessageDigest sm3 = MessageDigest.getInstance("SM3");

        int numberOfUpdates = Math.min(20, dataSize / 50);
        int chunkSize = dataSize / numberOfUpdates;

        for (int i = 0; i < numberOfUpdates; i++) {
            int offset = i * chunkSize;
            int len = (i == numberOfUpdates - 1) ? dataSize - offset : chunkSize;
            sm3.update(inputData, offset, len);
        }

        return sm3.digest();
    }

    /**
     * SM3 complete workflow: create instance + small data processing
     */
    @Benchmark
    public byte[] sm3CompleteWorkflowSmallData() throws NoSuchAlgorithmException {
        MessageDigest sm3 = MessageDigest.getInstance("SM3");

        // Test small data block (32 bytes)
        byte[] smallData = new byte[32];
        System.arraycopy(inputData, 0, smallData, 0, 32);

        return sm3.digest(smallData);
    }

    /**
     * SM3 complete workflow: create instance + use pre-allocated buffer
     */
    @Benchmark
    public byte[] sm3CompleteWorkflowPreAllocatedBuffer() throws NoSuchAlgorithmException, DigestException {
        MessageDigest sm3 = MessageDigest.getInstance("SM3");
        sm3.update(inputData);

        // Use pre-allocated buffer
        byte[] buffer = new byte[32]; // SM3 output length
        sm3.digest(buffer, 0, 32);

        return buffer;
    }

    // ============ High Frequency Usage Scenario Tests ============

    /**
     * High frequency scenario: continuous multiple complete hash computations
     */
    @Benchmark
    public byte[][] sm3HighFrequencyMultipleHashes() throws NoSuchAlgorithmException {
        byte[][] results = new byte[5][];

        for (int i = 0; i < 5; i++) {
            MessageDigest sm3 = MessageDigest.getInstance("SM3");
            results[i] = sm3.digest(inputData);
        }

        return results;
    }

    /**
     * Batch processing scenario: process multiple data blocks of different sizes
     */
    @Benchmark
    public byte[][] sm3BatchProcessingVariousDataSizes() throws NoSuchAlgorithmException {
        byte[][] results = new byte[4][];

        // Process data blocks of different sizes
        int[] sizes = {64, 256, 1024, Math.min(4096, dataSize)};

        for (int i = 0; i < sizes.length; i++) {
            MessageDigest sm3 = MessageDigest.getInstance("SM3");
            byte[] data = new byte[sizes[i]];
            System.arraycopy(inputData, 0, data, 0, sizes[i]);
            results[i] = sm3.digest(data);
        }

        return results;
    }

    // ============ Memory Usage Pattern Tests ============

    /**
     * Memory intensive: create instance + large data block processing
     */
    @Benchmark
    public byte[] sm3MemoryIntensiveLargeData() throws NoSuchAlgorithmException {
        MessageDigest sm3 = MessageDigest.getInstance("SM3");

        // Multiple updates with large data blocks each time
        int chunkSize = Math.max(8192, dataSize / 4);
        for (int i = 0; i < dataSize; i += chunkSize) {
            int len = Math.min(chunkSize, dataSize - i);
            sm3.update(inputData, i, len);
        }

        return sm3.digest();
    }

    /**
     * Memory friendly: create instance + small chunk data processing
     */
    @Benchmark
    public byte[] sm3MemoryFriendlySmallChunks() throws NoSuchAlgorithmException {
        MessageDigest sm3 = MessageDigest.getInstance("SM3");

        // Many updates with small data blocks each time
        int chunkSize = 64;
        for (int i = 0; i < dataSize; i += chunkSize) {
            int len = Math.min(chunkSize, dataSize - i);
            sm3.update(inputData, i, len);
        }

        return sm3.digest();
    }

    // ============ Clone and Reset Tests ============

    /**
     * Clone scenario: create instance + partial update + clone + complete computation
     */
    @Benchmark
    public byte[] sm3CloneScenarioPartialUpdate() throws NoSuchAlgorithmException, CloneNotSupportedException {
        MessageDigest sm3 = MessageDigest.getInstance("SM3");

        // Update partial data first
        int partialSize = Math.min(1024, dataSize / 2);
        sm3.update(inputData, 0, partialSize);

        // Clone instance
        MessageDigest cloned = (MessageDigest) sm3.clone();

        // Complete remaining computation
        cloned.update(inputData, partialSize, dataSize - partialSize);
        return cloned.digest();
    }

    /**
     * Reset scenario: create instance + multiple calculations
     */
    @Benchmark
    public byte[][] sm3ResetScenarioMultipleCalculations() throws NoSuchAlgorithmException {
        MessageDigest sm3 = MessageDigest.getInstance("SM3");
        byte[][] results = new byte[3][];

        // Perform multiple calculations, relying on digest() auto-reset
        for (int i = 0; i < 3; i++) {
            sm3.update(inputData);
            results[i] = sm3.digest(); // digest() will auto-reset
        }

        return results;
    }

    // ============ Edge Case Tests ============

    /**
     * Empty data processing: create instance + process empty data
     */
    @Benchmark
    public byte[] sm3EmptyDataProcessing() throws NoSuchAlgorithmException {
        MessageDigest sm3 = MessageDigest.getInstance("SM3");

        // Process empty data
        byte[] emptyData = new byte[0];
        return sm3.digest(emptyData);
    }

    /**
     * Single byte data: create instance + process single byte
     */
    @Benchmark
    public byte[] sm3SingleByteProcessing() throws NoSuchAlgorithmException {
        MessageDigest sm3 = MessageDigest.getInstance("SM3");

        // Process single byte data
        sm3.update(inputData[0]);
        return sm3.digest();
    }
}