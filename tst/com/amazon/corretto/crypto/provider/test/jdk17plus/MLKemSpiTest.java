// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static org.junit.jupiter.api.Assertions.*;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import com.amazon.corretto.crypto.provider.EvpKemPrivateKey;
import com.amazon.corretto.crypto.provider.EvpKemPublicKey;
import com.amazon.corretto.crypto.provider.MlKemGen;
import com.amazon.corretto.crypto.provider.MLKemSpi;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.Security;
import java.security.spec.NamedParameterSpec;
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

      // 3. Create encapsulator directly using SPI with NamedParameterSpec
      NamedParameterSpec paramSpec = new NamedParameterSpec(getParameterSpecName(parameterSet));
      KEMSpi.EncapsulatorSpi encapsulator = kemSpi.engineNewEncapsulator(
          keyPair.getPublic(), paramSpec, null);
      assertNotNull(encapsulator, "Encapsulator should not be null");
      
      // Verify encapsulator properties
      assertEquals(32, encapsulator.engineSecretSize(), "Secret size should be 32 bytes");
      int expectedCiphertextSize = getCiphertextSize(parameterSet);
      assertEquals(expectedCiphertextSize, encapsulator.engineEncapsulationSize(), 
                   "Ciphertext size should match expected value");

      // 4. Encapsulate to get ciphertext + shared secret
      KEM.Encapsulated encapsulated = encapsulator.engineEncapsulate(0, 32, "ML-KEM");
      assertNotNull(encapsulated, "Encapsulated result should not be null");
      assertNotNull(encapsulated.key(), "Shared secret should not be null");
      assertNotNull(encapsulated.encapsulation(), "Ciphertext should not be null");
      
      SecretKey originalSecret = encapsulated.key();
      byte[] ciphertext = encapsulated.encapsulation();
      
      assertEquals(32, originalSecret.getEncoded().length, 
                   "Shared secret should be 32 bytes");
      assertEquals(expectedCiphertextSize, ciphertext.length, 
                   "Ciphertext size should match expected value");

      // 5. Create decapsulator directly using SPI with NamedParameterSpec
      KEMSpi.DecapsulatorSpi decapsulator = kemSpi.engineNewDecapsulator(
          keyPair.getPrivate(), paramSpec);
      assertNotNull(decapsulator, "Decapsulator should not be null");
      
      // Verify decapsulator properties
      assertEquals(32, decapsulator.engineSecretSize(), "Secret size should be 32 bytes");
      assertEquals(expectedCiphertextSize, decapsulator.engineEncapsulationSize(), 
                   "Ciphertext size should match expected value");

      // 6. Decapsulate ciphertext to recover shared secret
      SecretKey recoveredSecret = decapsulator.engineDecapsulate(ciphertext, 0, 32, "ML-KEM");
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
      NamedParameterSpec paramSpec512 = new NamedParameterSpec("ML-KEM-512");
      KEMSpi.DecapsulatorSpi decapsulator = kemSpi.engineNewDecapsulator(
          keyPair.getPrivate(), paramSpec512);
      byte[] invalidCiphertext = new byte[10]; // Wrong size
      
      assertThrows(Exception.class, () -> {
        decapsulator.engineDecapsulate(invalidCiphertext, 0, 32, "ML-KEM");
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
      NamedParameterSpec paramSpec512 = new NamedParameterSpec("ML-KEM-512");
      KEMSpi.EncapsulatorSpi encapsulator = kemSpi.engineNewEncapsulator(
          keyPair.getPublic(), paramSpec512, null);
      
      // This will call native methods
      KEM.Encapsulated encapsulated = encapsulator.engineEncapsulate(0, 32, "ML-KEM");
      
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

      // Create parameter specs for each parameter set
      NamedParameterSpec paramSpec512 = new NamedParameterSpec("ML-KEM-512");
      NamedParameterSpec paramSpec768 = new NamedParameterSpec("ML-KEM-768");
      NamedParameterSpec paramSpec1024 = new NamedParameterSpec("ML-KEM-1024");

      // Test encapsulator creation with matching parameter sets
      assertNotNull(kemSpi512.engineNewEncapsulator(keyPair512.getPublic(), paramSpec512, null));
      assertNotNull(kemSpi768.engineNewEncapsulator(keyPair768.getPublic(), paramSpec768, null));
      assertNotNull(kemSpi1024.engineNewEncapsulator(keyPair1024.getPublic(), paramSpec1024, null));

      // Test decapsulator creation with matching parameter sets
      assertNotNull(kemSpi512.engineNewDecapsulator(keyPair512.getPrivate(), paramSpec512));
      assertNotNull(kemSpi768.engineNewDecapsulator(keyPair768.getPrivate(), paramSpec768));
      assertNotNull(kemSpi1024.engineNewDecapsulator(keyPair1024.getPrivate(), paramSpec1024));

      System.out.println("✅ Parameter set validation successful");

    } catch (Exception e) {
      e.printStackTrace();
      fail("Parameter set validation test failed: " + e.getMessage());
    }
  }

  @Test
  void testEncapsulatorWithNamedParameterSpec() throws Exception {
    System.out.println("Testing encapsulator with NamedParameterSpec...");
    testWithNamedParameterSpec("ML-KEM-512", 512);
    testWithNamedParameterSpec("ML-KEM-768", 768);
    testWithNamedParameterSpec("ML-KEM-1024", 1024);
    System.out.println("✅ Encapsulator NamedParameterSpec tests passed");
  }

  @Test
  void testDecapsulatorWithNamedParameterSpec() throws Exception {
    System.out.println("Testing decapsulator with NamedParameterSpec...");
    testDecapsulatorWithNamedParameterSpec("ML-KEM-512", 512);
    testDecapsulatorWithNamedParameterSpec("ML-KEM-768", 768);
    testDecapsulatorWithNamedParameterSpec("ML-KEM-1024", 1024);
    System.out.println("✅ Decapsulator NamedParameterSpec tests passed");
  }

  @Test
  void testParameterSpecMismatch() throws Exception {
    System.out.println("Testing parameter spec mismatch...");
    
    // Test that wrong parameter spec throws exception
    MlKemGen keyGen768 = new MlKemGen.MlKemGen768(provider);
    KeyPair keyPair768 = keyGen768.generateKeyPair();
    
    MLKemSpi kemSpi = new MLKemSpi.MLKem768();
    NamedParameterSpec wrongSpec = new NamedParameterSpec("ML-KEM-512"); // Wrong for 768 key
    
    assertThrows(InvalidAlgorithmParameterException.class, 
        () -> kemSpi.engineNewEncapsulator(keyPair768.getPublic(), wrongSpec, null));
    assertThrows(InvalidAlgorithmParameterException.class, 
        () -> kemSpi.engineNewDecapsulator(keyPair768.getPrivate(), wrongSpec));
        
    System.out.println("✅ Parameter spec mismatch tests passed");
  }

  @Test
  void testNullParameterSpec() throws Exception {
    System.out.println("Testing null parameter spec...");
    
    // Test that null parameter spec throws InvalidAlgorithmParameterException
    MlKemGen keyGen512 = new MlKemGen.MlKemGen512(provider);
    KeyPair keyPair512 = keyGen512.generateKeyPair();
    
    MLKemSpi kemSpi = new MLKemSpi.MLKem512();
    
    // Should throw InvalidAlgorithmParameterException for null spec
    assertThrows(InvalidAlgorithmParameterException.class, 
        () -> kemSpi.engineNewEncapsulator(keyPair512.getPublic(), null, null),
        "Should throw InvalidAlgorithmParameterException for null parameter spec in encapsulator");
    
    assertThrows(InvalidAlgorithmParameterException.class, 
        () -> kemSpi.engineNewDecapsulator(keyPair512.getPrivate(), null),
        "Should throw InvalidAlgorithmParameterException for null parameter spec in decapsulator");
    
    System.out.println("✅ Null parameter spec tests passed");
  }

  private void testWithNamedParameterSpec(String paramName, int expectedParamSet) throws Exception {
    // Generate key pair for the expected parameter set
    MlKemGen keyGen = createKeyGen(expectedParamSet);
    KeyPair keyPair = keyGen.generateKeyPair();
    
    // Create KEM SPI with NamedParameterSpec
    MLKemSpi kemSpi = createKemSpi(expectedParamSet);
    NamedParameterSpec spec = new NamedParameterSpec(paramName);
    
    // Should succeed - parameter spec matches key
    KEMSpi.EncapsulatorSpi encapsulator = kemSpi.engineNewEncapsulator(keyPair.getPublic(), spec, null);
    assertNotNull(encapsulator);
    
    // Test encapsulation works
    KEM.Encapsulated encapsulated = encapsulator.engineEncapsulate(0, 32, "ML-KEM");
    assertNotNull(encapsulated.key());
    assertNotNull(encapsulated.encapsulation());
  }

  private void testDecapsulatorWithNamedParameterSpec(String paramName, int expectedParamSet) throws Exception {
    // Generate key pair for the expected parameter set
    MlKemGen keyGen = createKeyGen(expectedParamSet);
    KeyPair keyPair = keyGen.generateKeyPair();
    
    // Create KEM SPI with NamedParameterSpec
    MLKemSpi kemSpi = createKemSpi(expectedParamSet);
    NamedParameterSpec spec = new NamedParameterSpec(paramName);
    
    // Should succeed - parameter spec matches key
    KEMSpi.DecapsulatorSpi decapsulator = kemSpi.engineNewDecapsulator(keyPair.getPrivate(), spec);
    assertNotNull(decapsulator);
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

  // Helper method to get parameter spec name
  private String getParameterSpecName(int parameterSet) {
    switch (parameterSet) {
      case 512:
        return "ML-KEM-512";
      case 768:
        return "ML-KEM-768";
      case 1024:
        return "ML-KEM-1024";
      default:
        throw new IllegalArgumentException("Unsupported parameter set: " + parameterSet);
    }
  }
}
