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
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package org.openjdk.bench.java.security;

import org.openjdk.jmh.annotations.*;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.concurrent.TimeUnit;

/**
 * SM4 Performance Benchmark
 */
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
@State(Scope.Benchmark)
@Fork(value = 1, jvmArgsAppend = {"-Xms1g", "-Xmx1g"})
@Warmup(iterations = 2, time = 2)
@Measurement(iterations = 3, time = 3)
public class SM4Bench {

    @Param({"1024", "4096", "16384", "65536"})
    private int dataSize;

    @Param({"ECB", "CBC", "CTR", "GCM"})
    private String mode;

    @Param({"NoPadding", "PKCS7Padding"})
    private String padding;

    private byte[] data;
    private byte[] key;
    private byte[] iv;
    private Cipher cipher;

    @Setup(Level.Trial)
    public void setup() throws Exception {
        // Test data - adjust size for NoPadding mode
        int actualDataSize = dataSize;
        if (padding.equals("NoPadding")) {
            // Ensure data size is multiple of 16 for NoPadding
            actualDataSize = (dataSize / 16) * 16;
            if (actualDataSize == 0) actualDataSize = 16;
        }

        data = new byte[actualDataSize];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) (i & 0xFF);
        }

        // SM4 key (16 bytes)
        key = new byte[]{
                0x01, 0x23, 0x45, 0x67, (byte) 0x89, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF,
                (byte) 0xFE, (byte) 0xDC, (byte) 0xBA, (byte) 0x98, 0x76, 0x54, 0x32, 0x10
        };

        // IV for modes that need it
        iv = new byte[]{
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
        };

        // Setup cipher - GCM and CTR mode only supports NoPadding
        String actualPadding = padding;
        if ((mode.equals("GCM") || mode.equals("CTR")) && padding.equals("PKCS7Padding")) {
            actualPadding = "NoPadding";
        }
        String transformation = "SM4/" + mode + "/" + actualPadding;
        cipher = Cipher.getInstance(transformation);
    }

    /**
     * Test SM4 Native implementation (all modes)
     */
    @Benchmark
    public byte[] nativeImplementation() throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(key, "SM4");

        if (mode.equals("ECB")) {
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        } else if (mode.equals("GCM")) {
            // Generate truly unique IV for each GCM operation to avoid reuse
            byte[] gcmIv = new byte[12];
            long nanoTime = System.nanoTime();
            // Use both nanoTime and thread ID to ensure uniqueness
            long threadId = Thread.currentThread().getId();
            for (int i = 0; i < 8; i++) {
                gcmIv[i] = (byte) ((nanoTime >>> (i * 8)) & 0xFF);
            }
            for (int i = 8; i < 12; i++) {
                gcmIv[i] = (byte) ((threadId >>> ((i - 8) * 8)) & 0xFF);
            }
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, gcmIv);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
        } else {
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        }

        byte[] result = cipher.doFinal(data);
        return result;
    }

    /**
     * Test Java implementation for all modes (ECB, CBC, CTR, GCM)
     */
    @Benchmark
    public byte[] javaImplementation() throws Exception {
        // Force Java implementation
        System.setProperty("sm4.native.disable", "true");

        try {
            SecretKeySpec keySpec = new SecretKeySpec(key, "SM4");

            if (mode.equals("ECB")) {
                cipher.init(Cipher.ENCRYPT_MODE, keySpec);
            } else if (mode.equals("GCM")) {
                // Generate unique IV for each GCM operation to avoid reuse
                byte[] gcmIv = new byte[12];
                long nanoTime = System.nanoTime();
                long threadId = Thread.currentThread().getId();
                for (int i = 0; i < 8; i++) {
                    gcmIv[i] = (byte) ((nanoTime >>> (i * 8)) & 0xFF);
                }
                for (int i = 8; i < 12; i++) {
                    gcmIv[i] = (byte) ((threadId >>> ((i - 8) * 8)) & 0xFF);
                }
                GCMParameterSpec gcmSpec = new GCMParameterSpec(128, gcmIv);
                cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
            } else {
                // CBC and CTR modes
                IvParameterSpec ivSpec = new IvParameterSpec(iv);
                cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
            }

            byte[] result = cipher.doFinal(data);
            return result;
        } finally {
            System.clearProperty("sm4.native.disable");
        }
    }

    /**
     * Baseline test for overhead measurement (disabled to save time)
     */
    // @Benchmark
    public byte[] baseline() {
        byte[] copy = new byte[data.length];
        System.arraycopy(data, 0, copy, 0, data.length);
        return copy;
    }
}
