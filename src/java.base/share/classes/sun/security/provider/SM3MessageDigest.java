/*
 * Copyright (C) 2022, 2023, THL A29 Limited, a Tencent company. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. THL A29 Limited designates
 * this particular file as subject to the "Classpath" exception as provided
 * in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License version 2 for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

package sun.security.provider;

import java.security.DigestException;
import java.security.MessageDigest;
import java.security.AccessController;
import java.security.PrivilegedAction;
import sun.security.util.OpenSSLUtil;

/**
 * SM3 hash in compliance with GB/T 32905-2016.
 *
 * This implementation automatically chooses between OpenSSL native implementation
 * (when available) for better performance, or pure Java implementation as fallback.
 * 
 * The OpenSSL implementation uses a "create-use-destroy" pattern for better GC performance,
 * avoiding long-term native resource management.
 * 
 * <p><b>OpenSSL Integration:</b> This class uses the centralized OpenSSL loading mechanism
 * provided by {@link OpenSSLUtil}. To use a custom OpenSSL library, set the system property
 * {@code jdk.openssl.cryptoLibPath} to the absolute path of libcrypto.so.
 * 
 * <p><b>Note:</b> This class is not thread-safe. If multiple threads need to use
 * the same MessageDigest instance, they must provide external synchronization or
 * use separate instances per thread.
 */
public final class SM3MessageDigest extends MessageDigest implements Cloneable {

    private static final int SM3_DIGEST_LENGTH = 32;

    // OpenSSL availability detection
    private static final boolean opensslAvailable;

    // Engine implementation (strategy pattern)
    private SM3Engine engine;

    static {
        boolean available = false;

        try {
            // Check if OpenSSL crypto library is loaded via OpenSSLUtil
            if (OpenSSLUtil.isOpenSSLLoaded()) {
                // Load OpenSSL SM3 native library
                @SuppressWarnings("removal")
                Void unused = AccessController.doPrivileged((PrivilegedAction<Void>) () -> {
                    System.loadLibrary("opensslsm3");
                    return null;
                });

                // Verify if OpenSSL supports SM3
                available = nativeSupportsSM3();
            }
        } catch (UnsatisfiedLinkError | SecurityException e) {
            // Native library loading failed,use pure Java implementation
            available = false;
        }

        opensslAvailable = available;
    }

    public SM3MessageDigest() {
        super("SM3");

        // Choose implementation based on OpenSSL availability
        if (opensslAvailable) {
            engine = new NativeSM3EngineImpl();
        } else {
            engine = new SM3EngineImpl();
        }
    }

    /**
     * Private constructor for cloning
     */
    private SM3MessageDigest(SM3Engine engine) {
        super("SM3");
        this.engine = engine;
    }

    @Override
    protected int engineGetDigestLength() {
        return SM3_DIGEST_LENGTH;
    }

    @Override
    protected void engineUpdate(byte input) {
        engine.update(input);
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int length) {
        if (length == 0) {
            return;
        }

        if (input == null) {
            throw new NullPointerException("Input array cannot be null");
        }

        if ((offset < 0) || (length < 0) || (offset > input.length - length)) {
            throw new ArrayIndexOutOfBoundsException("Invalid offset or length");
        }

        engine.update(input, offset, length);
    }

    @Override
    protected byte[] engineDigest() {
        return engine.doFinal();
    }

    @Override
    protected int engineDigest(byte[] buf, int offset, int length)
            throws DigestException {
        if (buf == null) {
            throw new NullPointerException("Output buffer cannot be null");
        }

        if (length < SM3_DIGEST_LENGTH) {
            throw new DigestException("Output buffer too small. Required: " +
                    SM3_DIGEST_LENGTH + ", got: " + length);
        }

        if ((offset < 0) || (offset > buf.length - SM3_DIGEST_LENGTH)) {
            throw new ArrayIndexOutOfBoundsException("Invalid offset");
        }

        engine.doFinal(buf, offset);
        return SM3_DIGEST_LENGTH;
    }

    @Override
    protected void engineReset() {
        engine.reset();
    }

    @Override
    public Object clone() throws CloneNotSupportedException {
        SM3Engine clonedEngine = engine.clone();
        return new SM3MessageDigest(clonedEngine);
    }

    /**
     * Check if current instance is using OpenSSL implementation
     * @return true if using OpenSSL implementation
     */
    public boolean isUsingOpenSSL() {
        return engine instanceof NativeSM3EngineImpl;
    }

    /**
     * Check if system supports OpenSSL SM3 implementation
     * @return true if OpenSSL SM3 is supported
     */
    public static boolean isOpenSSLAvailable() {
        return opensslAvailable;
    }

    /**
     * Create an SM3Engine implementation (OpenSSL if available, Java fallback).
     * This method returns the best available SM3Engine implementation without
     * throwing exceptions, making it ideal for use in crypto implementations.
     *
     * @return SM3Engine implementation (native or pure Java)
     */
    public static SM3Engine newSM3Engine() {
        if (opensslAvailable) {
            return new NativeSM3EngineImpl();
        } else {
            return new SM3EngineImpl();
        }
    }

    // ======================== Native Methods ========================

    /**
     * Check if native OpenSSL supports SM3 algorithm
     * @return true if SM3 is supported
     */
    private static native boolean nativeSupportsSM3();
}
