// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "buffer.h"
#include "env.h"
#include "generated-headers.h"
#include "util.h"
#include "auto_free.h"
#include <openssl/evp.h>

using namespace AmazonCorrettoCryptoProvider;

JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_MLKemSpi_nativeEncapsulate(
    JNIEnv* pEnv, jclass, jlong evpKeyPtr, jbyteArray ciphertextArray, jbyteArray sharedSecretArray)
{
    try {
        raii_env env(pEnv);
        EVP_PKEY* key = reinterpret_cast<EVP_PKEY*>(evpKeyPtr);
        
        // Create EVP context
        EVP_PKEY_CTX_auto ctx = EVP_PKEY_CTX_auto::from(EVP_PKEY_CTX_new(key, NULL));
        if (!ctx.isInitialized()) {
            throw_java_ex(EX_RUNTIME_CRYPTO, "Failed to create EVP context");
        }
        
        JBinaryBlob ciphertext(pEnv, nullptr, ciphertextArray);
        JBinaryBlob shared_secret(pEnv, nullptr, sharedSecretArray);
        
        size_t ciphertext_len = env->GetArrayLength(ciphertextArray);  
        size_t shared_secret_len = 32;  // ML-KEM always produces 32 bytes
        
        CHECK_OPENSSL(EVP_PKEY_encapsulate(ctx, ciphertext.get(), &ciphertext_len,
                                          shared_secret.get(), &shared_secret_len));
        
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
    }
}



JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_MLKemSpi_nativeDecapsulate(
    JNIEnv* pEnv, jclass, jlong evpKeyPtr, jbyteArray ciphertextArray, jbyteArray sharedSecretArray)
{
    try {
        raii_env env(pEnv);
        EVP_PKEY* key = reinterpret_cast<EVP_PKEY*>(evpKeyPtr);
        
        EVP_PKEY_CTX_auto ctx = EVP_PKEY_CTX_auto::from(EVP_PKEY_CTX_new(key, NULL));
        if (!ctx.isInitialized()) {
            throw_java_ex(EX_RUNTIME_CRYPTO, "Failed to create EVP context");
        }
        
        jsize ciphertext_array_len = env->GetArrayLength(ciphertextArray);
        
        JBinaryBlob ciphertext(pEnv, nullptr, ciphertextArray);
        JBinaryBlob shared_secret(pEnv, nullptr, sharedSecretArray);
        
        size_t shared_secret_len = 32;  // ML-KEM always produces 32 bytes
        CHECK_OPENSSL(EVP_PKEY_decapsulate(ctx, shared_secret.get(), &shared_secret_len,
                                          ciphertext.get(), ciphertext_array_len));
        
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
    }
}


