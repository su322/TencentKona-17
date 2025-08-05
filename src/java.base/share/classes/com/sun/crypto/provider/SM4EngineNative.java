/*
 * Copyright (C) 2025, THL A29 Limited, a Tencent company. All rights reserved.
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

package com.sun.crypto.provider;

import sun.security.util.OpenSSLUtil;
import java.security.AccessController;
import java.security.PrivilegedAction;

/**
 * Native SM4 Engine using OpenSSL for improved performance.
 */
final class SM4EngineNative implements SM4Engine {

    private static boolean nativeAvailable = false;

    private final byte[] key;
    private final boolean forEncryption;

    static {
        try {
            if (OpenSSLUtil.isOpenSSLLoaded()) {
                @SuppressWarnings("removal")
                Void unused = AccessController.doPrivileged((PrivilegedAction<Void>) () -> {
                    System.loadLibrary("opensslsm4");
                    return null;
                });
                nativeAvailable = initNative();
            }
        } catch (UnsatisfiedLinkError e) {
            System.err.println("Failed to load native SM4 library: " + e.getMessage());
            nativeAvailable = false;
        }
    }

    /**
     * Constructor for SM4EngineNative instance
     * @param key SM4 key (16 bytes)
     * @param forEncryption true for encryption, false for decryption
     */
    public SM4EngineNative(byte[] key, boolean forEncryption) {
        if (key.length != 16) {
            throw new IllegalArgumentException("SM4 key must be 16 bytes");
        }
        this.key = key.clone();
        this.forEncryption = forEncryption;
    }

    /**
     * Check if native SM4 engine is available.
     * @return true if native engine is available
     */
    public static boolean isAvailable() {
        return nativeAvailable;
    }

    /**
     * Process a single 16-byte block using native SM4 implementation
     * @param input input data
     * @param inputOffset offset in input array
     * @param output output buffer
     * @param outputOffset offset in output array
     */
    @Override
    public void processBlock(byte[] input, int inputOffset, byte[] output, int outputOffset) {
        nativeProcessBlock(key, input, inputOffset, output, outputOffset, forEncryption);
    }

    // Native methods
    private static native boolean initNative();

    static native void nativeProcessBlock(byte[] key, byte[] input, int inputOffset,
                                         byte[] output, int outputOffset, boolean encrypt);
}
