// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "buffer.h"
#include "env.h"
#include "generated-headers.h"
#include "util.h"
#include "auto_free.h"
#include <openssl/evp.h>

using namespace AmazonCorrettoCryptoProvider;

JNIEXPORT jobjectArray JNICALL Java_com_amazon_corretto_crypto_provider_MLKemSpi_nativeEncapsulate(
    JNIEnv* pEnv, jclass, jlong evpKeyPtr)
{
    try {
        raii_env env(pEnv);
        EVP_PKEY* key = reinterpret_cast<EVP_PKEY*>(evpKeyPtr);
        
        // Create EVP context from the key
        EVP_PKEY_CTX_auto ctx = EVP_PKEY_CTX_auto::from(EVP_PKEY_CTX_new(key, NULL));
        if (!ctx.isInitialized()) {
            throw_java_ex(EX_RUNTIME_CRYPTO, "Failed to create EVP context");
        }
        
        // Get buffer sizes automatically from the key
        size_t ciphertext_len, shared_secret_len;
        CHECK_OPENSSL(EVP_PKEY_encapsulate(ctx, NULL, &ciphertext_len, NULL, &shared_secret_len));
        
        // Allocate buffers
        SimpleBuffer ciphertext(ciphertext_len);
        SimpleBuffer shared_secret(shared_secret_len);
        
        // Perform encapsulation
        CHECK_OPENSSL(EVP_PKEY_encapsulate(ctx, ciphertext.get_buffer(), &ciphertext_len,
                                          shared_secret.get_buffer(), &shared_secret_len));
        
        // Create Java byte[][] array: [ciphertext, shared_secret]
        jobjectArray resultArray = env->NewObjectArray(2, env->FindClass("[B"), nullptr);
        if (!resultArray) {
            throw_java_ex(EX_OOM, "Unable to allocate result array");
        }
        
        // Create ciphertext byte array
        jbyteArray jCiphertext = env->NewByteArray(ciphertext_len);
        if (!jCiphertext) {
            throw_java_ex(EX_OOM, "Unable to allocate ciphertext array");
        }
        // This may throw, if it does we'll just keep the exception state as we return
        env->SetByteArrayRegion(jCiphertext, 0, ciphertext_len, (jbyte*)ciphertext.get_buffer());
        
        // Create shared secret byte array
        jbyteArray jSharedSecret = env->NewByteArray(shared_secret_len);
        if (!jSharedSecret) {
            throw_java_ex(EX_OOM, "Unable to allocate shared secret array");
        }
        // This may throw, if it does we'll just keep the exception state as we return
        env->SetByteArrayRegion(jSharedSecret, 0, shared_secret_len, (jbyte*)shared_secret.get_buffer());
        
        // Set array elements: result[0] = ciphertext, result[1] = shared_secret
        env->SetObjectArrayElement(resultArray, 0, jCiphertext);
        env->SetObjectArrayElement(resultArray, 1, jSharedSecret);
        
        return resultArray;
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return nullptr;
    }
}


JNIEXPORT jbyteArray JNICALL Java_com_amazon_corretto_crypto_provider_MLKemSpi_nativeDecapsulate(
    JNIEnv* pEnv, jclass, jlong evpKeyPtr, jbyteArray cipherText)
{
    try {
        raii_env env(pEnv);
        EVP_PKEY* key = reinterpret_cast<EVP_PKEY*>(evpKeyPtr);
        
        // Get ciphertext length from Java array
        jsize ciphertext_len = env->GetArrayLength(cipherText);
        JBinaryBlob ciphertext(pEnv, nullptr, cipherText);
        
        // Create EVP context from the key
        EVP_PKEY_CTX_auto ctx = EVP_PKEY_CTX_auto::from(EVP_PKEY_CTX_new(key, NULL));
        if (!ctx.isInitialized()) {
            throw_java_ex(EX_RUNTIME_CRYPTO, "Failed to create EVP context");
        }
        
        
        // Get shared secret size automatically from the key
        size_t shared_secret_len;
        CHECK_OPENSSL(EVP_PKEY_decapsulate(ctx, NULL, &shared_secret_len, 
                                          ciphertext.get(), ciphertext_len));
        
        // Allocate buffer for shared secret
        SimpleBuffer shared_secret(shared_secret_len);
        
        // Perform decapsulation
        CHECK_OPENSSL(EVP_PKEY_decapsulate(ctx, shared_secret.get_buffer(), &shared_secret_len,
                                          ciphertext.get(), ciphertext_len));
        
        // Create Java byte array for shared secret
        jbyteArray jSharedSecret = env->NewByteArray(shared_secret_len);
        if (!jSharedSecret) {
            throw_java_ex(EX_OOM, "Unable to allocate shared secret array");
        }
        // This may throw, if it does we'll just keep the exception state as we return
        env->SetByteArrayRegion(jSharedSecret, 0, shared_secret_len, (jbyte*)shared_secret.get_buffer());
        
        return jSharedSecret;
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return nullptr;
    }
}

