/*
 * Copyright (C) 2022, 2025, THL A29 Limited, a Tencent company. All rights reserved.
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

import java.security.InvalidKeyException;

/**
 * SM4 cipher implementation with native acceleration support.
 *
 * This class provides both Java and native implementations of the SM4 block cipher.
 * When available, it uses native code through SM4EngineNative for better
 * performance. Falls back to pure Java implementation when native support is unavailable.
 */
final class SM4Crypt extends SymmetricCipher {

    private SM4Engine engine;

    @Override
    int getBlockSize() {
        return 16;
    }

    /**
     * Creates the appropriate SM4 engine implementation based on availability.
     * Prefers native implementation when available, falls back to Java implementation.
     */
    private static SM4Engine createEngine(byte[] key, boolean encrypt) {
        if (SM4EngineNative.isAvailable()) {
            return new SM4EngineNative(key, encrypt);
        } else {
            return new SM4EngineImpl(key, encrypt);
        }
    }

    @Override
    void init(boolean decrypting, String algorithm, byte[] key)
            throws InvalidKeyException {
        if (!algorithm.equalsIgnoreCase("SM4")) {
            throw new InvalidKeyException("The algorithm must be SM4");
        }

        // Create the appropriate engine implementation
        engine = createEngine(key, !decrypting);
    }

    @Override
    void encryptBlock(byte[] plain, int plainOffset,
                      byte[] cipher, int cipherOffset) {
        engine.processBlock(plain, plainOffset, cipher, cipherOffset);
    }

    @Override
    void decryptBlock(byte[] cipher, int cipherOffset,
                      byte[] plain, int plainOffset) {
        engine.processBlock(cipher, cipherOffset, plain, plainOffset);
    }
}
