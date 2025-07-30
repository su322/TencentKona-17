/*
 * Copyright (C) 2022, 2024, THL A29 Limited, a Tencent company. All rights reserved.
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

/**
 * Internal SM3 digest engine interface.
 *
 * This interface provides an abstraction for different SM3 implementation strategies,
 * allowing the SM3MessageDigest to work with both pure Java and native OpenSSL
 * implementations transparently.
 */
public interface SM3Engine extends Cloneable {
    /**
     * Update digest with single byte
     *
     * @param input the byte to be added to the digest
     */
    void update(byte input);

    /**
     * Update digest with entire byte array
     */
    void update(byte[] input);

    /**
     * Update digest with byte array
     *
     * @param input  the byte array to be added to the digest
     * @param offset the offset in the array to start from
     * @param length the number of bytes to use
     */
    void update(byte[] input, int offset, int length);

    /**
     * Complete digest calculation and return result
     *
     * @return the computed digest as a byte array
     */
    byte[] doFinal();

    /**
     * Complete digest calculation into provided buffer
     *
     * @param out the output buffer to write the digest to
     */
    void doFinal(byte[] out);

    /**
     * Complete digest calculation into provided buffer
     *
     * @param out    the output buffer to write the digest to
     * @param offset the offset in the output buffer to start writing
     */
    void doFinal(byte[] out, int offset);

    /**
     * Reset engine state for reuse
     */
    void reset();

    /**
     * Clone engine with current state
     *
     * @return a copy of this engine with the same state
     */
    SM3Engine clone() throws CloneNotSupportedException;
}
