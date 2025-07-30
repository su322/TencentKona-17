/*
 * Copyright (c) 2025, Oracle and/or its affiliates. All rights reserved.
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

package sun.security.provider;

import java.io.ByteArrayOutputStream;
import java.security.ProviderException;

/**
 * OpenSSL native SM3 implementation.
 */
final class NativeSM3EngineImpl implements SM3Engine {

    private static final int SM3_DIGEST_LENGTH = 32;

    private ByteArrayOutputStream dataBuffer;

    NativeSM3EngineImpl() {
        dataBuffer = new ByteArrayOutputStream();
    }

    private NativeSM3EngineImpl(ByteArrayOutputStream dataBuffer) {
        this.dataBuffer = dataBuffer;
    }

    @Override
    public void update(byte input) {
        dataBuffer.write(input);
    }

    @Override
    public void update(byte[] input) {
        dataBuffer.write(input, 0, input.length);
    }

    @Override
    public void update(byte[] input, int offset, int length) {
        dataBuffer.write(input, offset, length);
    }

    @Override
    public byte[] doFinal() {
        byte[] digest = new byte[SM3_DIGEST_LENGTH];
        doFinal(digest, 0);
        return digest;
    }

    @Override
    public void doFinal(byte[] out) {
        doFinal(out, 0);
    }

    @Override
    public void doFinal(byte[] out, int offset) {
        // Get accumulated data
        byte[] data = dataBuffer.toByteArray();

        // Create context, compute hash, and destroy context immediately
        int len = nativeDigest(data, 0, data.length, out, offset);
        if (len != SM3_DIGEST_LENGTH) {
            throw new ProviderException("OpenSSL SM3 digest length mismatch");
        }

        // Reset buffer for next use
        dataBuffer.reset();
    }

    @Override
    public void reset() {
        dataBuffer.reset();
    }

    @Override
    public SM3Engine clone() throws CloneNotSupportedException {
        // Use super.clone() to create shallow copy
        NativeSM3EngineImpl clone = (NativeSM3EngineImpl) super.clone();

        // Deep clone the data buffer
        ByteArrayOutputStream clonedBuffer = new ByteArrayOutputStream();
        byte[] currentData = dataBuffer.toByteArray();
        clonedBuffer.write(currentData, 0, currentData.length);
        clone.dataBuffer = clonedBuffer;

        return clone;
    }

    /**
     * Native method to compute SM3 digest in one call
     * @param data input data
     * @param dataOffset input data offset
     * @param dataLength input data length
     * @param digest output buffer
     * @param digestOffset output offset
     * @return number of bytes written to digest buffer
     */
    private static native int nativeDigest(byte[] data, int dataOffset, int dataLength,
                                           byte[] digest, int digestOffset);
}