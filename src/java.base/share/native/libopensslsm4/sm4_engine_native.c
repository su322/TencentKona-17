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

#include <jni.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <string.h>
#include <stdlib.h>

// Check OpenSSL version
#if OPENSSL_VERSION_NUMBER < 0x30500000L
#error "OpenSSL 3.5.0 or later is required for SM4 support"
#endif

// SM4 constants
#define SM4_KEY_SIZE 16
#define SM4_BLOCK_SIZE 16

// Global state for OpenSSL provider management
static jboolean native_available = JNI_FALSE;
static OSSL_PROVIDER *default_provider = NULL;
static OSSL_PROVIDER *legacy_provider = NULL;

// Using one-time operations for memory safety in long-running server environments

// Cached cipher object (only ECB needed)
static const EVP_CIPHER *sm4_ecb_cipher = NULL;

// Function declarations
static inline EVP_CIPHER_CTX* create_cipher_context(const EVP_CIPHER *cipher, const unsigned char *key,
                                                    const unsigned char *iv, int encrypt);

// Exception helper functions
static void throwRuntimeException(JNIEnv *env, const char *message) {
    jclass exceptionClass = (*env)->FindClass(env, "java/lang/RuntimeException");
    if (exceptionClass != NULL) {
        (*env)->ThrowNew(env, exceptionClass, message);
    }
}

// Helper function to initialize SM4-ECB cipher
static jboolean init_cached_ciphers() {
    if (sm4_ecb_cipher == NULL) {
        sm4_ecb_cipher = EVP_CIPHER_fetch(NULL, "SM4-ECB", NULL);
        if (!sm4_ecb_cipher) return JNI_FALSE;
    }
    return JNI_TRUE;
}

/*
 * Class:     com_sun_crypto_provider_SM4EngineNative
 * Method:    initNative
 * Signature: ()Z
 */
JNIEXPORT jboolean JNICALL Java_com_sun_crypto_provider_SM4EngineNative_initNative
(JNIEnv *env, jclass clazz) {
    // Initialize OpenSSL providers (required for OpenSSL 3.x)
    default_provider = OSSL_PROVIDER_load(NULL, "default");
    if (!default_provider) {
        return JNI_FALSE;
    }

    // Try to load legacy provider for additional algorithm support
    legacy_provider = OSSL_PROVIDER_load(NULL, "legacy");
    // Legacy provider is optional, so we don't fail if it's not available

    // Initialize cached ciphers
    if (!init_cached_ciphers()) {
        // Clean up on failure
        if (legacy_provider) {
            OSSL_PROVIDER_unload(legacy_provider);
            legacy_provider = NULL;
        }
        OSSL_PROVIDER_unload(default_provider);
        default_provider = NULL;
        return JNI_FALSE;
    }

    native_available = JNI_TRUE;
    return JNI_TRUE;
}

/*
 * Native single-block SM4 processing using ECB mode only.
 *
 * Why only ECB?
 * - All cipher modes (ECB/CBC/CTR/GCM) ultimately need single-block SM4 encryption
 * - Mode-specific logic (IV handling, chaining, counters, authentication) is handled in Java layer
 * - ECB is the pure SM4 algorithm without mode complications
 * - This design maintains clean separation: Java handles modes, native handles algorithm
 *
 * Class:     com_sun_crypto_provider_SM4EngineNative
 * Method:    nativeProcessBlock
 * Signature: ([B[BI[BIZ)V
 */
JNIEXPORT void JNICALL Java_com_sun_crypto_provider_SM4EngineNative_nativeProcessBlock
(JNIEnv *env, jclass clazz, jbyteArray keyArray, jbyteArray inputArray, jint inputOffset,
 jbyteArray outputArray, jint outputOffset, jboolean encrypt) {

    if (!native_available) {
        throwRuntimeException(env, "Native SM4 engine not available");
        return;
    }

    // Get array pointers
    jbyte *key = (*env)->GetByteArrayElements(env, keyArray, NULL);
    jbyte *input = (*env)->GetByteArrayElements(env, inputArray, NULL);
    jbyte *output = (*env)->GetByteArrayElements(env, outputArray, NULL);

    if (!key || !input || !output) {
        if (key) (*env)->ReleaseByteArrayElements(env, keyArray, key, JNI_ABORT);
        if (input) (*env)->ReleaseByteArrayElements(env, inputArray, input, JNI_ABORT);
        if (output) (*env)->ReleaseByteArrayElements(env, outputArray, output, JNI_ABORT);
        throwRuntimeException(env, "Failed to access array data");
        return;
    }

    // Create one-time cipher context (no reuse, memory safe)
    EVP_CIPHER_CTX *cipher_ctx = EVP_CIPHER_CTX_new();
    if (!cipher_ctx) {
        (*env)->ReleaseByteArrayElements(env, keyArray, key, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, inputArray, input, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, outputArray, output, JNI_ABORT);
        throwRuntimeException(env, "Failed to create cipher context");
        return;
    }

    // Initialize with SM4-ECB cipher
    if (EVP_CipherInit_ex(cipher_ctx, sm4_ecb_cipher, NULL, (unsigned char*)key, NULL, encrypt ? 1 : 0) != 1) {
        EVP_CIPHER_CTX_free(cipher_ctx);
        (*env)->ReleaseByteArrayElements(env, keyArray, key, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, inputArray, input, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, outputArray, output, JNI_ABORT);
        throwRuntimeException(env, "Failed to initialize cipher context");
        return;
    }

    // Disable padding for block-level operations (SM4Engine handles complete 16-byte blocks)
    if (EVP_CIPHER_CTX_set_padding(cipher_ctx, 0) != 1) {
        EVP_CIPHER_CTX_free(cipher_ctx);
        (*env)->ReleaseByteArrayElements(env, keyArray, key, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, inputArray, input, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, outputArray, output, JNI_ABORT);
        throwRuntimeException(env, "Failed to disable padding");
        return;
    }

    // Process single 16-byte block (no final step needed for complete blocks with no padding)
    int outlen = 0;
    if (EVP_CipherUpdate(cipher_ctx, (unsigned char*)(output + outputOffset), &outlen,
                        (const unsigned char*)(input + inputOffset), 16) != 1) {
        EVP_CIPHER_CTX_free(cipher_ctx);
        (*env)->ReleaseByteArrayElements(env, keyArray, key, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, inputArray, input, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, outputArray, output, JNI_ABORT);
        throwRuntimeException(env, "SM4 block processing failed");
        return;
    }

    // Verify that exactly 16 bytes were processed
    if (outlen != 16) {
        EVP_CIPHER_CTX_free(cipher_ctx);
        (*env)->ReleaseByteArrayElements(env, keyArray, key, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, inputArray, input, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, outputArray, output, JNI_ABORT);
        throwRuntimeException(env, "SM4 block processing: unexpected output length");
        return;
    }

    // Clean up
    EVP_CIPHER_CTX_free(cipher_ctx);
    (*env)->ReleaseByteArrayElements(env, keyArray, key, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, inputArray, input, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, outputArray, output, 0); // Commit output changes
}

// JNI library unload callback
JNIEXPORT void JNICALL JNI_OnUnload(JavaVM *vm, void *reserved) {
    // No thread-local contexts to clean up in one-time operation mode

    // Free cached cipher object
    if (sm4_ecb_cipher) {
        EVP_CIPHER_free((EVP_CIPHER*)sm4_ecb_cipher);
        sm4_ecb_cipher = NULL;
    }

    // Clean up OpenSSL providers
    if (default_provider) {
        OSSL_PROVIDER_unload(default_provider);
        default_provider = NULL;
    }
    if (legacy_provider) {
        OSSL_PROVIDER_unload(legacy_provider);
        legacy_provider = NULL;
    }

    native_available = JNI_FALSE;
}
