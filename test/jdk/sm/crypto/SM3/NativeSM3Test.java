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
 * @summary Test Native SM3 implementation using OpenSSL
 * @library /test/lib
 * @modules java.base/sun.security.provider
 *          java.base/sun.security.util
 * @run main/othervm NativeSM3Test
 * @run main/othervm/policy=test.policy NativeSM3Test
 */

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Arrays;
import java.util.Locale;
import java.util.HexFormat;

import sun.security.provider.SM3MessageDigest;
import sun.security.util.OpenSSLUtil;

public class NativeSM3Test {

    // Test vectors from GB/T 32905-2016
    private static final String TEST_MESSAGE_1 = "abc";
    private static final String EXPECTED_HASH_1 =
            "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0";

    private static final String TEST_MESSAGE_2 =
            "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";
    private static final String EXPECTED_HASH_2 =
            "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732";

    // Empty message test
    private static final String TEST_MESSAGE_3 = "";
    private static final String EXPECTED_HASH_3 =
            "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b";

    public static void main(String[] args) throws Exception {
        System.out.println("=== Native SM3 Test ===");

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

        // Run tests
        testNativeSM3Availability();
        testBasicHashing();
        testIncrementalHashing();
        testLargeMessage();
        testEdgeCases();
        testConsistencyWithJavaImpl();

        System.out.println("PASS: All Native SM3 tests completed successfully");
    }

    /**
     * Test if Native SM3 is available and working
     */
    private static void testNativeSM3Availability() throws Exception {
        System.out.println("\n--- Testing Native SM3 Availability ---");

        // Check if OpenSSL is loaded
        boolean opensslLoaded = OpenSSLUtil.isOpenSSLLoaded();
        System.out.println("OpenSSL loaded: " + opensslLoaded);

        if (!opensslLoaded) {
            throw new Exception("OpenSSL should be loaded with provided library path");
        }

        // Check if SM3 native implementation is available
        boolean nativeAvailable = SM3MessageDigest.isOpenSSLAvailable();
        System.out.println("Native SM3 available: " + nativeAvailable);

        if (!nativeAvailable) {
            throw new Exception("Native SM3 should be available");
        }

        // Create SM3 instance and verify it's using native implementation
        SM3MessageDigest sm3 = new SM3MessageDigest();
        boolean usingNative = sm3.isUsingOpenSSL();
        System.out.println("Using native implementation: " + usingNative);

        if (!usingNative) {
            throw new Exception("SM3MessageDigest should use native implementation");
        }

        System.out.println("Native SM3 is available and active");
    }

    /**
     * Test basic hashing with known test vectors
     */
    private static void testBasicHashing() throws Exception {
        System.out.println("\n--- Testing Basic Hashing ---");

        MessageDigest sm3 = MessageDigest.getInstance("SM3");

        // Test vector 1
        testVector(sm3, TEST_MESSAGE_1, EXPECTED_HASH_1, "Test vector 1");

        // Test vector 2
        testVector(sm3, TEST_MESSAGE_2, EXPECTED_HASH_2, "Test vector 2");

        // Test vector 3 (empty message)
        testVector(sm3, TEST_MESSAGE_3, EXPECTED_HASH_3, "Test vector 3 (empty)");

        System.out.println("Basic hashing tests passed");
    }

    /**
     * Test incremental hashing (update multiple times)
     */
    private static void testIncrementalHashing() throws Exception {
        System.out.println("\n--- Testing Incremental Hashing ---");

        MessageDigest sm3 = MessageDigest.getInstance("SM3");

        // Hash "abc" incrementally
        sm3.update("a".getBytes());
        sm3.update("b".getBytes());
        sm3.update("c".getBytes());

        byte[] result = sm3.digest();
        String hexResult = HexFormat.of().formatHex(result);

        if (!EXPECTED_HASH_1.equals(hexResult)) {
            throw new Exception("Incremental hashing failed. Expected: " +
                    EXPECTED_HASH_1 + ", Got: " + hexResult);
        }

        System.out.println("Incremental hashing test passed");
    }

    /**
     * Test with large message
     */
    private static void testLargeMessage() throws Exception {
        System.out.println("\n--- Testing Large Message ---");

        MessageDigest sm3 = MessageDigest.getInstance("SM3");

        // Create a large message (1MB)
        byte[] largeMessage = new byte[1024 * 1024];
        Arrays.fill(largeMessage, (byte) 'A');

        byte[] result = sm3.digest(largeMessage);

        if (result.length != 32) {
            throw new Exception("SM3 should produce 32-byte hash, got: " + result.length);
        }

        System.out.println("Large message test passed (hash length: " + result.length + ")");
    }

    /**
     * Test edge cases
     */
    private static void testEdgeCases() throws Exception {
        System.out.println("\n--- Testing Edge Cases ---");

        MessageDigest sm3 = MessageDigest.getInstance("SM3");

        // Test with null handling
        try {
            sm3.update(null, 0, 0);
            throw new Exception("Should throw exception for null input");
        } catch (IllegalArgumentException | NullPointerException e) {
            System.out.println("Null input properly handled: " + e.getClass().getSimpleName());
        }

        // Test reset functionality
        sm3.update(TEST_MESSAGE_1.getBytes());
        sm3.reset();
        byte[] result = sm3.digest();
        String hexResult = HexFormat.of().formatHex(result);

        if (!EXPECTED_HASH_3.equals(hexResult)) {
            throw new Exception("Reset functionality failed");
        }

        System.out.println("Edge cases test passed");
    }

    /**
     * Test consistency between native and Java implementations
     */
    private static void testConsistencyWithJavaImpl() throws Exception {
        System.out.println("\n--- Testing Native vs Java Consistency ---");

        // Temporarily disable native implementation for comparison
        String originalPath = System.getProperty("jdk.openssl.cryptoLibPath");
        System.clearProperty("jdk.openssl.cryptoLibPath");

        try {
            // Create Java-only instance
            MessageDigest javaSM3 = MessageDigest.getInstance("SM3");

            // Restore native implementation
            System.setProperty("jdk.openssl.cryptoLibPath", originalPath);
            MessageDigest nativeSM3 = MessageDigest.getInstance("SM3");

            // Test with various inputs
            String[] testInputs = {
                    "",
                    "a",
                    "abc",
                    "message digest",
                    "abcdefghijklmnopqrstuvwxyz",
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
            };

            for (String input : testInputs) {
                byte[] javaResult = javaSM3.digest(input.getBytes());
                byte[] nativeResult = nativeSM3.digest(input.getBytes());

                if (!Arrays.equals(javaResult, nativeResult)) {
                    throw new Exception("Inconsistent results for input: " + input +
                            "\nJava:   " + HexFormat.of().formatHex(javaResult) +
                            "\nNative: " + HexFormat.of().formatHex(nativeResult));
                }
            }

        } finally {
            // Restore original property
            if (originalPath != null) {
                System.setProperty("jdk.openssl.cryptoLibPath", originalPath);
            }
        }

        System.out.println("Native and Java implementations are consistent");
    }

    /**
     * Test a specific test vector
     */
    private static void testVector(MessageDigest md, String message, String expected, String testName)
            throws Exception {
        byte[] result = md.digest(message.getBytes());
        String hexResult = HexFormat.of().formatHex(result);

        if (!expected.equals(hexResult)) {
            throw new Exception(testName + " failed. Expected: " + expected +
                    ", Got: " + hexResult);
        }

        System.out.println(testName + " passed");
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