// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static org.junit.jupiter.api.Assertions.*;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import com.amazon.corretto.crypto.provider.EvpKemPrivateKey;
import com.amazon.corretto.crypto.provider.EvpKemPublicKey;
import com.amazon.corretto.crypto.provider.MlKemGen;
import com.amazon.corretto.crypto.provider.MLKemSpi;
import java.security.KeyPair;
import java.security.Security;
import javax.crypto.KEM;
import javax.crypto.KEMSpi;
import javax.crypto.SecretKey;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

public class MLKemSpiTest {

  private AmazonCorrettoCryptoProvider provider;

  @BeforeEach
  void setUp() {
    provider = new AmazonCorrettoCryptoProvider();
    Security.addProvider(provider);
  }

  @ParameterizedTest
  @ValueSource(ints = {512, 768, 1024})
  void testMLKemSpiDirectRoundTrip(int parameterSet) {
    System.out.println("Testing ML-KEM-" + parameterSet + " SPI direct round-trip...");

    try {
      // 1. Generate key pair using MlKemGen
      MlKemGen keyGen = createKeyGen(parameterSet);
      KeyPair keyPair = keyGen.generateKeyPair();
      
      assertNotNull(keyPair, "KeyPair should not be null");
      assertNotNull(keyPair.getPrivate(), "Private key should not be null");
      assertNotNull(keyPair.getPublic(), "Public key should not be null");
      
      assertTrue(keyPair.getPrivate() instanceof EvpKemPrivateKey, 
                 "Private key should be EvpKemPrivateKey");
      assertTrue(keyPair.getPublic() instanceof EvpKemPublicKey, 
                 "Public key should be EvpKemPublicKey");

      // 2. Create SPI instance directly
      MLKemSpi kemSpi = createKemSpi(parameterSet);
      assertNotNull(kemSpi, "KEM SPI should not be null");

      // 3. Create encapsulator directly using SPI
      KEMSpi.EncapsulatorSpi encapsulator = kemSpi.engineNewEncapsulator(
          keyPair.getPublic(), null, null);
      assertNotNull(encapsulator, "Encapsulator should not be null");
      
      // Verify encapsulator properties
      assertEquals(32, encapsulator.engineSecretSize(), "Secret size should be 32 bytes");
      int expectedCiphertextSize = getCiphertextSize(parameterSet);
      assertEquals(expectedCiphertextSize, encapsulator.engineEncapsulationSize(), 
                   "Ciphertext size should match expected value");

      // 4. Encapsulate to get ciphertext + shared secret
      KEM.Encapsulated encapsulated = encapsulator.engineEncapsulate(0, 32, "Generic");
      assertNotNull(encapsulated, "Encapsulated result should not be null");
      assertNotNull(encapsulated.key(), "Shared secret should not be null");
      assertNotNull(encapsulated.encapsulation(), "Ciphertext should not be null");
      
      SecretKey originalSecret = encapsulated.key();
      byte[] ciphertext = encapsulated.encapsulation();
      
      assertEquals(32, originalSecret.getEncoded().length, 
                   "Shared secret should be 32 bytes");
      assertEquals(expectedCiphertextSize, ciphertext.length, 
                   "Ciphertext size should match expected value");

      // 5. Create decapsulator directly using SPI
      KEMSpi.DecapsulatorSpi decapsulator = kemSpi.engineNewDecapsulator(
          keyPair.getPrivate(), null);
      assertNotNull(decapsulator, "Decapsulator should not be null");
      
      // Verify decapsulator properties
      assertEquals(32, decapsulator.engineSecretSize(), "Secret size should be 32 bytes");
      assertEquals(expectedCiphertextSize, decapsulator.engineEncapsulationSize(), 
                   "Ciphertext size should match expected value");

      // 6. Decapsulate ciphertext to recover shared secret
      SecretKey recoveredSecret = decapsulator.engineDecapsulate(ciphertext, 0, 32, "Generic");
      assertNotNull(recoveredSecret, "Recovered secret should not be null");
      assertEquals(32, recoveredSecret.getEncoded().length, 
                   "Recovered secret should be 32 bytes");

      // 7. Assert: original secret equals recovered secret
      assertArrayEquals(originalSecret.getEncoded(), recoveredSecret.getEncoded(),
                        "Original and recovered secrets should match");

      System.out.println("✅ ML-KEM-" + parameterSet + " SPI direct round-trip successful");

    } catch (Exception e) {
      e.printStackTrace();
      fail("ML-KEM-" + parameterSet + " SPI direct round-trip failed: " + e.getMessage());
    }
  }

  @Test
  void testSpiInstanceCreation() {
    System.out.println("Testing SPI instance creation...");

    try {
      // Test all supported parameter sets
      int[] parameterSets = {512, 768, 1024};
      
      for (int parameterSet : parameterSets) {
        MLKemSpi kemSpi = createKemSpi(parameterSet);
        assertNotNull(kemSpi, "KEM SPI should not be null for " + parameterSet);
        System.out.println("✅ ML-KEM-" + parameterSet + " SPI instance created successfully");
      }

    } catch (Exception e) {
      e.printStackTrace();
      fail("SPI instance creation failed: " + e.getMessage());
    }
  }

  @Test
  void testErrorHandling() {
    System.out.println("Testing error handling...");

    try {
      // Generate a key pair
      MlKemGen keyGen = new MlKemGen.MlKemGen512(provider);
      KeyPair keyPair = keyGen.generateKeyPair();
      
      MLKemSpi kemSpi = new MLKemSpi.MLKem512();
      
      // Test null public key
      assertThrows(Exception.class, () -> {
        kemSpi.engineNewEncapsulator(null, null, null);
      }, "Should throw exception for null public key");
      
      // Test null private key
      assertThrows(Exception.class, () -> {
        kemSpi.engineNewDecapsulator(null, null);
      }, "Should throw exception for null private key");
      
      // Test invalid ciphertext
      KEMSpi.DecapsulatorSpi decapsulator = kemSpi.engineNewDecapsulator(
          keyPair.getPrivate(), null);
      byte[] invalidCiphertext = new byte[10]; // Wrong size
      
      assertThrows(Exception.class, () -> {
        decapsulator.engineDecapsulate(invalidCiphertext, 0, 32, "Generic");
      }, "Should throw exception for invalid ciphertext");

      System.out.println("✅ Error handling tests passed");

    } catch (Exception e) {
      e.printStackTrace();
      fail("Error handling test failed: " + e.getMessage());
    }
  }

  @Test
  void testJniIntegration() {
    System.out.println("Testing JNI integration...");

    try {
      // Test that native methods work correctly
      MlKemGen keyGen = new MlKemGen.MlKemGen512(provider);
      KeyPair keyPair = keyGen.generateKeyPair();
      
      MLKemSpi kemSpi = new MLKemSpi.MLKem512();
      KEMSpi.EncapsulatorSpi encapsulator = kemSpi.engineNewEncapsulator(
          keyPair.getPublic(), null, null);
      
      // This will call native methods
      KEM.Encapsulated encapsulated = encapsulator.engineEncapsulate(0, 32, "Generic");
      
      assertNotNull(encapsulated);
      assertNotNull(encapsulated.key());
      assertNotNull(encapsulated.encapsulation());

      System.out.println("✅ JNI integration successful");

    } catch (Exception e) {
      e.printStackTrace();
      fail("JNI integration test failed: " + e.getMessage());
    }
  }

  @Test
  void testParameterSetValidation() {
    System.out.println("Testing parameter set validation...");

    try {
      // Test that each SPI has correct parameter set
      MLKemSpi kemSpi512 = new MLKemSpi.MLKem512();
      MLKemSpi kemSpi768 = new MLKemSpi.MLKem768();
      MLKemSpi kemSpi1024 = new MLKemSpi.MLKem1024();

      // Generate key pairs for each parameter set
      MlKemGen keyGen512 = new MlKemGen.MlKemGen512(provider);
      MlKemGen keyGen768 = new MlKemGen.MlKemGen768(provider);
      MlKemGen keyGen1024 = new MlKemGen.MlKemGen1024(provider);

      KeyPair keyPair512 = keyGen512.generateKeyPair();
      KeyPair keyPair768 = keyGen768.generateKeyPair();
      KeyPair keyPair1024 = keyGen1024.generateKeyPair();

      // Test encapsulator creation with matching parameter sets
      assertNotNull(kemSpi512.engineNewEncapsulator(keyPair512.getPublic(), null, null));
      assertNotNull(kemSpi768.engineNewEncapsulator(keyPair768.getPublic(), null, null));
      assertNotNull(kemSpi1024.engineNewEncapsulator(keyPair1024.getPublic(), null, null));

      // Test decapsulator creation with matching parameter sets
      assertNotNull(kemSpi512.engineNewDecapsulator(keyPair512.getPrivate(), null));
      assertNotNull(kemSpi768.engineNewDecapsulator(keyPair768.getPrivate(), null));
      assertNotNull(kemSpi1024.engineNewDecapsulator(keyPair1024.getPrivate(), null));

      System.out.println("✅ Parameter set validation successful");

    } catch (Exception e) {
      e.printStackTrace();
      fail("Parameter set validation test failed: " + e.getMessage());
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

  // Helper method to create the appropriate SPI
  private MLKemSpi createKemSpi(int parameterSet) {
    switch (parameterSet) {
      case 512:
        return new MLKemSpi.MLKem512();
      case 768:
        return new MLKemSpi.MLKem768();
      case 1024:
        return new MLKemSpi.MLKem1024();
      default:
        throw new IllegalArgumentException("Unsupported parameter set: " + parameterSet);
    }
  }

  // Helper method to get expected ciphertext size
  private int getCiphertextSize(int parameterSet) {
    switch (parameterSet) {
      case 512:
        return 768;
      case 768:
        return 1088;
      case 1024:
        return 1568;
      default:
        throw new IllegalArgumentException("Unsupported parameter set: " + parameterSet);
    }
  }
}
