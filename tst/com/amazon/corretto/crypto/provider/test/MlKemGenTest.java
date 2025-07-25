// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static org.junit.jupiter.api.Assertions.*;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import com.amazon.corretto.crypto.provider.EvpKemPrivateKey;
import com.amazon.corretto.crypto.provider.EvpKemPublicKey;
import com.amazon.corretto.crypto.provider.MlKemGen;
import java.security.KeyPair;
import java.security.Security;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

public class MlKemGenTest {

  private AmazonCorrettoCryptoProvider provider;

  @BeforeEach
  void setUp() {
    provider = new AmazonCorrettoCryptoProvider();
    Security.addProvider(provider);
  }

  @ParameterizedTest
  @ValueSource(ints = {512, 768, 1024})
  void testMlKemKeyGeneration(int parameterSet) {
    System.out.println("Testing ML-KEM-" + parameterSet + " key generation...");

    try {
      MlKemGen keyGen = createKeyGen(parameterSet);
      KeyPair keyPair = keyGen.generateKeyPair();

      // Basic assertions
      assertNotNull(keyPair, "KeyPair should not be null");
      assertNotNull(keyPair.getPrivate(), "Private key should not be null");
      assertNotNull(keyPair.getPublic(), "Public key should not be null");

      // Type assertions
      assertTrue(
          keyPair.getPrivate() instanceof EvpKemPrivateKey,
          "Private key should be EvpKemPrivateKey");
      assertTrue(
          keyPair.getPublic() instanceof EvpKemPublicKey, "Public key should be EvpKemPublicKey");

      System.out.println("✅ ML-KEM-" + parameterSet + " key generation successful");

    } catch (Exception e) {
      e.printStackTrace();
      fail("ML-KEM-" + parameterSet + " key generation failed: " + e.getMessage());
    }
  }

  @Test
  void testJniIntegration() {
    System.out.println("Testing JNI integration...");

    try {
      // Test that JNI method generateEvpMlKemKey(512) is working
      MlKemGen.MlKemGen512 keyGen = new MlKemGen.MlKemGen512(provider);
      KeyPair keyPair = keyGen.generateKeyPair();

      assertNotNull(keyPair);
      assertNotNull(keyPair.getPrivate());
      assertNotNull(keyPair.getPublic());

      System.out.println("✅ JNI integration successful");

    } catch (Exception e) {
      e.printStackTrace();
      fail("JNI integration test failed: " + e.getMessage());
    }
  }

  // Helper method to create the appropriate key generator
  private MlKemGen createKeyGen(int parameterSet) {
    switch (parameterSet) {
      case 512:
        return new MlKemGen.MlKemGen512(provider);
      case 768:
        return new MlKemGen.MlKemGen768(provider);
      case 1024:
        return new MlKemGen.MlKemGen1024(provider);
      default:
        throw new IllegalArgumentException("Unsupported parameter set: " + parameterSet);
    }
  }
}
