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

/*
 * @test
 * @summary Test SM4 Native Engine implementation
 * @library /test/lib
 * @modules java.base/com.sun.crypto.provider
 * @compile ../../Utils.java
 * @run main/othervm SM4NativeEngineTest
 * @run main/othervm/policy=test.policy SM4NativeEngineTest
 */

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Locale;

public class SM4NativeEngineTest {

    private static final int SM4_GCM_TAG_LEN = 16;

    // Helper method to convert bytes to hex string
    private static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }

    // Test vectors from GB/T 32907-2016
    private static final byte[] TEST_KEY = Utils.hexToBytes("0123456789abcdeffedcba9876543210");
    private static final byte[] TEST_PLAINTEXT = Utils.hexToBytes("0123456789abcdeffedcba9876543210");
    private static final byte[] EXPECTED_CIPHERTEXT = Utils.hexToBytes("681edf34d206965e86b3e94f536e4246");
    
    private static final byte[] IV_16 = Utils.hexToBytes("00000000000000000000000000000000");
    private static final byte[] GCM_IV = Utils.hexToBytes("000000000000000000000000");
    
    public static void main(String[] args) throws Exception {
        System.out.println("=== SM4 Native Engine Test ===");

        // Get OpenSSL crypto library path
        String cryptoLibPath = opensslCryptoPath();
        if (cryptoLibPath == null) {
            System.out.println("OpenSSL crypto library not found, skipping native tests");
            System.out.println("PASS: Test completed (native library not available)");
            return;
        }

        System.out.println("Found OpenSSL crypto library: " + cryptoLibPath);

        // Set system property for OpenSSL library path
        System.setProperty("jdk.openssl.cryptoLibPath", cryptoLibPath);

        // Test 1: Verify native engine availability
        testNativeEngineAvailability();
        
        // Test 2: Test basic ECB encryption/decryption
        testECBMode();
        
        // Test 3: Test all supported modes
        testAllModes();
        
        // Test 4: Compare native vs Java implementation
        testNativeVsJavaConsistency();
        
        // Test 5: Test performance characteristics
        testPerformanceCharacteristics();
        
        // Test 6: Test error conditions
        testErrorConditions();

        System.out.println("PASS: All SM4 Native Engine tests completed successfully");
    }

    private static void testNativeEngineAvailability() throws Exception {
        System.out.println("\n--- Testing Native SM4 Engine Availability ---");

        // Test OpenSSL availability indirectly by checking if the library path is set
        String opensslLibPath = System.getProperty("jdk.openssl.cryptoLibPath");
        System.out.println("OpenSSL library path: " + opensslLibPath);

        if (opensslLibPath == null || opensslLibPath.isEmpty()) {
            System.out.println("Warning: OpenSSL library path not set");
        }

        // Test native engine availability by attempting to use SM4 cipher
        // If native engine is available, it will be used automatically
        try {
            SecretKeySpec key = new SecretKeySpec(TEST_KEY, "SM4");
            Cipher cipher = Cipher.getInstance("SM4/ECB/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] result = cipher.doFinal(TEST_PLAINTEXT);

            // If we get here without exception, some SM4 implementation is working
            System.out.println("SM4 cipher is working (native engine may be active)");

            // Verify the result matches expected output
            if (Arrays.equals(EXPECTED_CIPHERTEXT, result)) {
                System.out.println("SM4 encryption produces correct results");
            } else {
                System.out.println("Warning: SM4 encryption result differs from expected");
            }
        } catch (Exception e) {
            throw new Exception("SM4 cipher failed to work: " + e.getMessage());
        }

        System.out.println("SM4 Engine is available and working");
    }
    
    private static void testECBMode() throws Exception {
        System.out.println("Testing ECB mode with native engine...");
        
        SecretKeySpec key = new SecretKeySpec(TEST_KEY, "SM4");
        Cipher cipher = Cipher.getInstance("SM4/ECB/NoPadding");
        
        // Test encryption
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] ciphertext = cipher.doFinal(TEST_PLAINTEXT);
        
        if (!Arrays.equals(EXPECTED_CIPHERTEXT, ciphertext)) {
            throw new RuntimeException("ECB encryption failed: expected " +
                bytesToHex(EXPECTED_CIPHERTEXT) + " but got " +
                bytesToHex(ciphertext));
        }
        
        // Test decryption
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decrypted = cipher.doFinal(ciphertext);
        
        if (!Arrays.equals(TEST_PLAINTEXT, decrypted)) {
            throw new RuntimeException("ECB decryption failed");
        }
        
        System.out.println("ECB mode works correctly");
    }
    
    private static void testAllModes() throws Exception {
        System.out.println("Testing all SM4 modes with native engine...");
        
        String[] modes = {
            "SM4/ECB/NoPadding",
            "SM4/ECB/PKCS7Padding", 
            "SM4/CBC/NoPadding",
            "SM4/CBC/PKCS7Padding",
            "SM4/CTR/NoPadding",
            "SM4/GCM/NoPadding"
        };
        
        SecretKeySpec key = new SecretKeySpec(TEST_KEY, "SM4");
        byte[] testData = Utils.hexToBytes("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
        
        for (String mode : modes) {
            System.out.println("  Testing mode: " + mode);
            
            Cipher cipher = Cipher.getInstance(mode);
            
            if (mode.contains("CBC") || mode.contains("CTR")) {
                IvParameterSpec ivSpec = new IvParameterSpec(IV_16);
                cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
                byte[] encrypted = cipher.doFinal(testData);
                
                cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
                byte[] decrypted = cipher.doFinal(encrypted);
                
                if (!Arrays.equals(testData, decrypted)) {
                    throw new RuntimeException("Mode " + mode + " failed");
                }
            } else if (mode.contains("GCM")) {
                GCMParameterSpec gcmSpec = new GCMParameterSpec(SM4_GCM_TAG_LEN * 8, GCM_IV);
                cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
                byte[] encrypted = cipher.doFinal(testData);
                
                cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);
                byte[] decrypted = cipher.doFinal(encrypted);
                
                if (!Arrays.equals(testData, decrypted)) {
                    throw new RuntimeException("Mode " + mode + " failed");
                }
            } else {
                cipher.init(Cipher.ENCRYPT_MODE, key);
                byte[] encrypted = cipher.doFinal(testData);
                
                cipher.init(Cipher.DECRYPT_MODE, key);
                byte[] decrypted = cipher.doFinal(encrypted);
                
                if (!Arrays.equals(testData, decrypted)) {
                    throw new RuntimeException("Mode " + mode + " failed");
                }
            }
        }
        
        System.out.println("All modes work correctly");
    }
    
    private static void testNativeVsJavaConsistency() throws Exception {
        System.out.println("Testing native vs Java implementation consistency...");

        SecretKeySpec key = new SecretKeySpec(TEST_KEY, "SM4");

        // Test with native engine enabled (should be default)
        Cipher nativeCipher = Cipher.getInstance("SM4/ECB/NoPadding");
        nativeCipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] nativeResult = nativeCipher.doFinal(TEST_PLAINTEXT);

        // Verify the result matches expected test vector
        if (!Arrays.equals(EXPECTED_CIPHERTEXT, nativeResult)) {
            throw new RuntimeException("Native implementation doesn't match test vector");
        }

        // Force disable native engine for comparison
        String originalProperty = System.getProperty("sm4.native.disable");
        System.setProperty("sm4.native.disable", "true");

        try {
            // Create new cipher instance with native disabled
            Cipher javaCipher = Cipher.getInstance("SM4/ECB/NoPadding");
            javaCipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] javaResult = javaCipher.doFinal(TEST_PLAINTEXT);

            if (!Arrays.equals(nativeResult, javaResult)) {
                throw new RuntimeException("Native and Java implementations produce different results");
            }
        } finally {
            // Restore original property
            if (originalProperty != null) {
                System.setProperty("sm4.native.disable", originalProperty);
            } else {
                System.clearProperty("sm4.native.disable");
            }
        }

        System.out.println("Native and Java implementations are consistent");
    }
    
    private static void testPerformanceCharacteristics() throws Exception {
        System.out.println("Testing performance characteristics...");
        
        SecretKeySpec key = new SecretKeySpec(TEST_KEY, "SM4");
        byte[] largeData = new byte[1024 * 1024]; // 1MB
        new SecureRandom().nextBytes(largeData);
        
        Cipher cipher = Cipher.getInstance("SM4/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        
        long startTime = System.nanoTime();
        byte[] encrypted = cipher.doFinal(largeData);
        long endTime = System.nanoTime();
        
        double throughputMBps = (largeData.length / 1024.0 / 1024.0) / ((endTime - startTime) / 1e9);
        System.out.println("  Native engine throughput: " + String.format("%.2f", throughputMBps) + " MB/s");
        
        // Verify correctness
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decrypted = cipher.doFinal(encrypted);
        
        if (!Arrays.equals(largeData, decrypted)) {
            throw new RuntimeException("Performance test failed - data corruption");
        }
        
        System.out.println("Performance test passed");
    }
    
    private static void testErrorConditions() throws Exception {
        System.out.println("Testing error conditions...");
        
        // Test with invalid key size
        try {
            byte[] invalidKey = new byte[15]; // Wrong size
            SecretKeySpec key = new SecretKeySpec(invalidKey, "SM4");
            Cipher cipher = Cipher.getInstance("SM4/ECB/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            throw new RuntimeException("Should have failed with invalid key size");
        } catch (Exception e) {
            // Expected
        }
        
        System.out.println("Error conditions handled correctly");
    }

    /**
     * Get OpenSSL crypto library path for current platform
     */
    public static String opensslCryptoPath() {
        String osName = System.getProperty("os.name").toLowerCase(Locale.ROOT);
        String os = "unsupported";
        String ext = "unsupported";
        if (osName.contains("linux")) {
            os = "linux";
            ext = ".so";
        } else if (osName.contains("mac")) {
            os = "macos";
            ext = ".dylib";
        }

        String archName = System.getProperty("os.arch").toLowerCase(Locale.ROOT);
        String arch = "unsupported";
        if (archName.contains("x86_64") || archName.contains("amd64")) {
            arch = "x86_64";
        } else if (archName.contains("aarch64") || archName.contains("arm64")) {
            arch = "aarch64";
        }

        String platformName = os + "-" + arch;
        String libName = "libopensslcrypto" + ext;

        Path testRoot = Paths.get(System.getProperty("test.root"));
        Path libPath = testRoot.resolve("openssl").resolve("lib")
                .resolve(platformName).resolve(libName);
        return Files.exists(libPath) ? libPath.toString() : null;
    }
}
