/*
 * Copyright (C) 2025, THL A29 Limited, a Tencent company. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. THL A29 Limited designates
 * this particular file as subject to the "Classpath" exception as provided
 * in the LICENSE file that accompanied this code.
 */

#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>

// SM3 digest length constant
#define SM3_DIGEST_LENGTH 32

// Exception class name constants
#define PROVIDER_EXCEPTION "java/security/ProviderException"
#define NULL_POINTER_EXCEPTION "java/lang/NullPointerException"
#define ILLEGAL_ARGUMENT_EXCEPTION "java/lang/IllegalArgumentException"
#define ARRAY_INDEX_OUT_OF_BOUNDS_EXCEPTION "java/lang/ArrayIndexOutOfBoundsException"

// Generic exception throwing function
static void throw_exception(JNIEnv *env, const char *exceptionName, const char *message) {
    jclass exceptionClass = (*env)->FindClass(env, exceptionName);
    if (exceptionClass != NULL) {
        (*env)->ThrowNew(env, exceptionClass, message);
        (*env)->DeleteLocalRef(env, exceptionClass);
    }
}

// Error handling helper function
static void handle_openssl_error(JNIEnv *env, const char *operation) {
    char error_buf[512];
    unsigned long error_code = ERR_get_error();

    if (error_code != 0) {
        ERR_error_string_n(error_code, error_buf, sizeof(error_buf));
        ERR_clear_error(); // Clear error queue
    } else {
        snprintf(error_buf, sizeof(error_buf), "OpenSSL error in %s", operation);
    }

    throw_exception(env, PROVIDER_EXCEPTION, error_buf);
}

/*
 * Check if OpenSSL supports SM3 algorithm
 * Class:     sun_security_provider_SM3MessageDigest
 * Method:    nativeSupportsSM3
 * Signature: ()Z
 */
JNIEXPORT jboolean JNICALL
Java_sun_security_provider_SM3MessageDigest_nativeSupportsSM3(JNIEnv *env, jclass clazz) {
    // Attempt to get SM3 algorithm implementation
    const EVP_MD *sm3_md = EVP_sm3();
    return (sm3_md != NULL) ? JNI_TRUE : JNI_FALSE;
}

/*
 * Complete SM3 digest calculation in one call
 * Creates context, processes data, finalizes, and destroys context immediately
 * Class:     sun_security_provider_NativeSM3EngineImpl
 * Method:    nativeDigest
 * Signature: ([BII[BI)I
 */
JNIEXPORT jint JNICALL
Java_sun_security_provider_NativeSM3EngineImpl_nativeDigest(JNIEnv *env, jclass clazz,
                                                         jbyteArray data, jint dataOffset, jint dataLength,
                                                         jbyteArray digest, jint digestOffset) {
    // Input validation
    if (data == NULL || digest == NULL) {
        throw_exception(env, NULL_POINTER_EXCEPTION, "Input arrays cannot be null");
        return 0;
    }

    if (dataLength < 0 || dataOffset < 0 || digestOffset < 0) {
        throw_exception(env, ILLEGAL_ARGUMENT_EXCEPTION, "Invalid offset or length");
        return 0;
    }

    // Check array bounds
    jsize data_array_length = (*env)->GetArrayLength(env, data);
    jsize digest_array_length = (*env)->GetArrayLength(env, digest);
    
    if (dataOffset + dataLength > data_array_length) {
        throw_exception(env, ARRAY_INDEX_OUT_OF_BOUNDS_EXCEPTION, "Data array bounds exceeded");
        return 0;
    }
    
    if (digestOffset + SM3_DIGEST_LENGTH > digest_array_length) {
        throw_exception(env, ARRAY_INDEX_OUT_OF_BOUNDS_EXCEPTION, "Digest array bounds exceeded");
        return 0;
    }

    // Create new context
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        handle_openssl_error(env, "EVP_MD_CTX_new");
        return 0;
    }

    // Initialize with SM3
    const EVP_MD *sm3_md = EVP_sm3();
    if (sm3_md == NULL) {
        EVP_MD_CTX_free(ctx);
        handle_openssl_error(env, "EVP_sm3 algorithm not available");
        return 0;
    }

    if (EVP_DigestInit_ex(ctx, sm3_md, NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        handle_openssl_error(env, "EVP_DigestInit_ex");
        return 0;
    }

    // Process data if any
    if (dataLength > 0) {
        jbyte *data_ptr = (*env)->GetPrimitiveArrayCritical(env, data, NULL);
        if (data_ptr == NULL) {
            EVP_MD_CTX_free(ctx);
            handle_openssl_error(env, "GetPrimitiveArrayCritical failed");
            return 0;
        }

        if (EVP_DigestUpdate(ctx, data_ptr + dataOffset, (size_t)dataLength) != 1) {
            (*env)->ReleasePrimitiveArrayCritical(env, data, data_ptr, JNI_ABORT);
            EVP_MD_CTX_free(ctx);
            handle_openssl_error(env, "EVP_DigestUpdate");
            return 0;
        }

        (*env)->ReleasePrimitiveArrayCritical(env, data, data_ptr, JNI_ABORT);
    }

    // Finalize digest
    unsigned char md_value[SM3_DIGEST_LENGTH];
    unsigned int md_len = 0;

    if (EVP_DigestFinal_ex(ctx, md_value, &md_len) != 1) {
        EVP_MD_CTX_free(ctx);
        handle_openssl_error(env, "EVP_DigestFinal_ex");
        return 0;
    }

    // Clean up context immediately
    EVP_MD_CTX_free(ctx);

    // Verify digest length
    if (md_len != SM3_DIGEST_LENGTH) {
        char error_msg[128];
        snprintf(error_msg, sizeof(error_msg),
                 "Unexpected SM3 digest length: %u (expected %d)", md_len, SM3_DIGEST_LENGTH);
        throw_exception(env, PROVIDER_EXCEPTION, error_msg);
        return 0;
    }

    // Copy result to Java array
    (*env)->SetByteArrayRegion(env, digest, digestOffset, SM3_DIGEST_LENGTH, (jbyte *)md_value);

    // Check if exception occurred
    if ((*env)->ExceptionCheck(env)) {
        return 0;
    }

    return SM3_DIGEST_LENGTH;
}