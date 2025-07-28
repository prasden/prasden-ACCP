// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import com.amazon.corretto.crypto.provider.EvpKemPrivateKey;
import com.amazon.corretto.crypto.provider.EvpKemPublicKey;
import com.amazon.corretto.crypto.provider.Loader;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import javax.crypto.DecapsulateException;
import javax.crypto.KEM;
import javax.crypto.KEMSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;

public abstract class MLKemSpi implements KEMSpi {

    private static final int SHARED_SECRET_SIZE = 32;
    protected static final int MLKEM_512 = 512;
    protected static final int MLKEM_768 = 768;
    protected static final int MLKEM_1024 = 1024;

    // ML-KEM size constants from aws-lc/crypto/fipsmodule/ml_kem/ml_kem.h
    private static final int MLKEM512_PUBLIC_KEY_BYTES = 800;
    private static final int MLKEM512_SECRET_KEY_BYTES = 1632;
    private static final int MLKEM512_CIPHERTEXT_BYTES = 768;

    private static final int MLKEM768_PUBLIC_KEY_BYTES = 1184;
    private static final int MLKEM768_SECRET_KEY_BYTES = 2400;
    private static final int MLKEM768_CIPHERTEXT_BYTES = 1088;

    private static final int MLKEM1024_PUBLIC_KEY_BYTES = 1568;
    private static final int MLKEM1024_SECRET_KEY_BYTES = 3168;
    private static final int MLKEM1024_CIPHERTEXT_BYTES = 1568;

    protected final int parameterSet;
    protected final int publicKeySize;
    protected final int privateKeySize;
    protected final int ciphertextSize;


    private static native byte[][] nativeEncapsulate(long evpKeyPtr);
    private static native byte[] nativeDecapsulate(long evpKeyPtr, byte[] cipherText);


    protected MLKemSpi(int parameterSet) {
        Loader.checkNativeLibraryAvailability();
        this.parameterSet = parameterSet;

        switch (parameterSet) {
            case MLKEM_512:
                this.publicKeySize = MLKEM512_PUBLIC_KEY_BYTES;
                this.privateKeySize = MLKEM512_SECRET_KEY_BYTES;
                this.ciphertextSize = MLKEM512_CIPHERTEXT_BYTES;
                break;
            case MLKEM_768:
                this.publicKeySize = MLKEM768_PUBLIC_KEY_BYTES;
                this.privateKeySize = MLKEM768_SECRET_KEY_BYTES;
                this.ciphertextSize = MLKEM768_CIPHERTEXT_BYTES;
                break;
            case MLKEM_1024:
                this.publicKeySize = MLKEM1024_PUBLIC_KEY_BYTES;
                this.privateKeySize = MLKEM1024_SECRET_KEY_BYTES;
                this.ciphertextSize = MLKEM1024_CIPHERTEXT_BYTES;
                break;
            default:
                throw new IllegalArgumentException("Invalid parameter set: " + parameterSet);
        }
    }


  @Override
  public KEMSpi.EncapsulatorSpi engineNewEncapsulator(
      PublicKey publicKey, AlgorithmParameterSpec spec, SecureRandom secureRandom)
      throws InvalidAlgorithmParameterException, InvalidKeyException {

    if(publicKey == null){
      throw new InvalidKeyException("Public key cannot be null");
    }
    if(secureRandom != null){
      throw new InvalidAlgorithmParameterException("SecureRandom must be null - AWS-LC handles its own randomness");
    }
    if(!(publicKey instanceof EvpKemPublicKey)){
      throw new InvalidKeyException("Unsupported public key type");
    }

    return new MLKemEncapsulatorSpi((EvpKemPublicKey) publicKey, ciphertextSize);
  }

  @Override
  public KEMSpi.DecapsulatorSpi engineNewDecapsulator(
      PrivateKey privateKey, AlgorithmParameterSpec spec)
      throws InvalidAlgorithmParameterException, InvalidKeyException {

    if (privateKey == null){
      throw new InvalidKeyException("Private key cannot be null");
    }

    if(!(privateKey instanceof EvpKemPrivateKey)){
      throw new InvalidKeyException("Unsupported private key type");
    }

    return new MLKemDecapsulatorSpi((EvpKemPrivateKey) privateKey, ciphertextSize);
    
  }

  public static final class MLKem512 extends MLKemSpi {
    public MLKem512() {
      super(MLKEM_512);
    }
  }

  public static final class MLKem768 extends MLKemSpi {
    public MLKem768() {
      super(MLKEM_768);
    }
  }

  public static final class MLKem1024 extends MLKemSpi {
    public MLKem1024() {
      super(MLKEM_1024);
    }
  }


  private static class MLKemEncapsulatorSpi implements KEMSpi.EncapsulatorSpi {
    private final EvpKemPublicKey publicKey;
    private final int ciphertextSize;
    
    MLKemEncapsulatorSpi(EvpKemPublicKey publicKey, int ciphertextSize) {
        this.publicKey = publicKey;
        this.ciphertextSize = ciphertextSize;
    }
    
    @Override
    public KEM.Encapsulated engineEncapsulate(int from, int to, String algorithm) {
        if (from < 0 || from > to || to > SHARED_SECRET_SIZE) {
            throw new IndexOutOfBoundsException("Invalid range: from=" + from + ", to=" + to);
        }
        if (algorithm == null) {
            throw new NullPointerException("Algorithm cannot be null");
        }
        if (from != 0 || to != SHARED_SECRET_SIZE || !"Generic".equals(algorithm)) {
            throw new UnsupportedOperationException("Only full secret with Generic algorithm is supported");
        }
        
        return publicKey.use(ptr -> {
            // Pass EVP_PKEY pointer directly - no raw key extraction
            byte[][] result = nativeEncapsulate(ptr);
            
            // Create secret key from the specified range
            byte[] secretRange = Arrays.copyOfRange(result[1], from, to);
            
            return new KEM.Encapsulated(
                new SecretKeySpec(secretRange, algorithm),
                result[0],  // ciphertext
                null        // params
            );
        });
    }

    

    @Override
    public int engineSecretSize() { 
        return SHARED_SECRET_SIZE; 
    }
    
    @Override
    public int engineEncapsulationSize() { 
        return ciphertextSize; 
    }


  }

  private static class MLKemDecapsulatorSpi implements KEMSpi.DecapsulatorSpi {
    private final EvpKemPrivateKey privateKey;
    private final int ciphertextSize;
    
    MLKemDecapsulatorSpi(EvpKemPrivateKey privateKey, int ciphertextSize) {
        this.privateKey = privateKey;
        this.ciphertextSize = ciphertextSize;
    }
    
    @Override
    public SecretKey engineDecapsulate(byte[] encapsulation, int from, int to, String algorithm) 
        throws DecapsulateException {
        // Validate inputs
        if (encapsulation == null) {
            throw new NullPointerException("Encapsulation cannot be null");
        }
        if (encapsulation.length != ciphertextSize) {
            throw new DecapsulateException("Invalid encapsulation size");
        }
        if (from < 0 || from > to || to > SHARED_SECRET_SIZE) {
            throw new IndexOutOfBoundsException("Invalid range: from=" + from + ", to=" + to);
        }
        if (algorithm == null) {
            throw new NullPointerException("Algorithm cannot be null");
        }
        if (from != 0 || to != SHARED_SECRET_SIZE || !"Generic".equals(algorithm)) {
            throw new UnsupportedOperationException("Only full secret with Generic algorithm is supported");
        }
        
        return privateKey.use(ptr -> {
            // Pass EVP_PKEY pointer directly - no raw key extraction
            byte[] sharedSecret = nativeDecapsulate(ptr, encapsulation);
            
            // Create secret key from the specified range
            byte[] secretRange = Arrays.copyOfRange(sharedSecret, from, to);
            return new SecretKeySpec(secretRange, algorithm);
        });
    }
    
    @Override
    public int engineSecretSize() { 
        return SHARED_SECRET_SIZE; 
    }
    
    @Override
    public int engineEncapsulationSize() { 
        return ciphertextSize; 
    }
  }


}
