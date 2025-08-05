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

/**
 * Common interface for SM4 engine implementations.
 * This interface provides a unified way to access both Java and native
 * SM4 engine implementations.
 */
interface SM4Engine {
    
    /**
     * Process a single 16-byte block.
     * 
     * @param input input data array
     * @param inputOffset offset in input array
     * @param output output data array  
     * @param outputOffset offset in output array
     */
    void processBlock(byte[] input, int inputOffset, byte[] output, int outputOffset);
}
