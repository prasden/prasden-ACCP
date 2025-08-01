// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.assertThrows;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import com.amazon.corretto.crypto.provider.EvpKemPrivateKey;
import com.amazon.corretto.crypto.provider.EvpKemPublicKey;
import com.amazon.corretto.crypto.provider.MlKemGen;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.NamedParameterSpec;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.KEM;
import javax.crypto.SecretKey;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledIf;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import java.security.PublicKey;


@DisabledIf("com.amazon.corretto.crypto.provider.test.MLKemInteroperabilityTest#isDisabled")
@Execution(ExecutionMode.CONCURRENT)
@ExtendWith(TestResultLogger.class)
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ)
public class MLKemInteroperabilityTest {
  private static final Provider NATIVE_PROVIDER = AmazonCorrettoCryptoProvider.INSTANCE;

  // TODO: remove this disablement when ACCP consumes an AWS-LC-FIPS release with ML-KEM
  public static boolean isDisabled() {
    return AmazonCorrettoCryptoProvider.INSTANCE.isFips()
        && !AmazonCorrettoCryptoProvider.INSTANCE.isExperimentalFips();
  }

  private static class TestParams {
    private final Provider encapsulatorProv;
    private final Provider decapsulatorProv;
    private final PrivateKey priv;
    private final PublicKey pub;
    private final String parameterSet;

    public TestParams(
        Provider encapsulatorProv,
        Provider decapsulatorProv,
        PrivateKey priv,
        PublicKey pub,
        String parameterSet) {
      this.encapsulatorProv = encapsulatorProv;
      this.decapsulatorProv = decapsulatorProv;
      this.priv = priv;
      this.pub = pub;
      this.parameterSet = parameterSet;
    }

    public String toString() {
      return String.format(
          "encapsulator: %s, decapsulator: %s, parameter set: %s",
          encapsulatorProv.getName(), decapsulatorProv.getName(), parameterSet);
    }
  }

  private static List<TestParams> getParams() throws Exception {
    List<TestParams> params = new ArrayList<TestParams>();
    for (String paramSet : new String[] {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"}) {
      // Generate key pair with ACCP
      KeyPair keyPair = KeyPairGenerator.getInstance(paramSet, NATIVE_PROVIDER).generateKeyPair();
      PublicKey nativePub = keyPair.getPublic();
      PrivateKey nativePriv = keyPair.getPrivate();

      // Convert ACCP native key to BouncyCastle key
      KeyFactory bcKf = KeyFactory.getInstance("ML-KEM", TestUtil.BC_PROVIDER);
      PublicKey bcPub = bcKf.generatePublic(new X509EncodedKeySpec(nativePub.getEncoded()));
      PrivateKey bcPriv = bcKf.generatePrivate(new PKCS8EncodedKeySpec(nativePriv.getEncoded()));

      Provider nativeProv = NATIVE_PROVIDER;
      Provider bcProv = TestUtil.BC_PROVIDER;

      // Test all cross-provider combinations
      params.add(new TestParams(nativeProv, nativeProv, nativePriv, nativePub, paramSet));
      params.add(new TestParams(nativeProv, bcProv, bcPriv, nativePub, paramSet));
      params.add(new TestParams(bcProv, nativeProv, nativePriv, bcPub, paramSet));
      params.add(new TestParams(bcProv, bcProv, bcPriv, bcPub, paramSet));
    }
    return params;
  }

  @ParameterizedTest
  @MethodSource("getParams")
  public void testInteropRoundTrips(TestParams params) throws Exception {
    // Get KEM instances
    KEM encapsulatorKem = KEM.getInstance(params.parameterSet, params.encapsulatorProv);
    KEM decapsulatorKem = KEM.getInstance(params.parameterSet, params.decapsulatorProv);
    
    // Create parameter spec
    NamedParameterSpec paramSpec = new NamedParameterSpec(params.parameterSet);
    
    // Encapsulate
    KEM.Encapsulator encapsulator = encapsulatorKem.newEncapsulator(params.pub, paramSpec, null);
    KEM.Encapsulated encapsulated = encapsulator.encapsulate();
    
    assertNotNull(encapsulated, "Encapsulated result should not be null");
    assertNotNull(encapsulated.key(), "Shared secret should not be null");
    assertNotNull(encapsulated.encapsulation(), "Ciphertext should not be null");
    
    SecretKey originalSecret = encapsulated.key();
    byte[] ciphertext = encapsulated.encapsulation();
    
    // Verify sizes
    assertEquals(32, originalSecret.getEncoded().length, "Shared secret should be 32 bytes");
    
    // Decapsulate
    KEM.Decapsulator decapsulator = decapsulatorKem.newDecapsulator(params.priv, paramSpec);
    SecretKey recoveredSecret = decapsulator.decapsulate(ciphertext);
    
    assertNotNull(recoveredSecret, "Recovered secret should not be null");
    assertEquals(32, recoveredSecret.getEncoded().length, "Recovered secret should be 32 bytes");
    
    // Verify secrets match
    assertArrayEquals(originalSecret.getEncoded(), recoveredSecret.getEncoded(),
                      "Original and recovered secrets should match");
  }

  @ParameterizedTest
  @ValueSource(strings = {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"})
  public void testKeyGeneration(String paramSet) throws Exception {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance(paramSet, NATIVE_PROVIDER);
    KeyPair keyPair = keyGen.generateKeyPair();

    assertNotNull(keyPair);
    assertNotNull(keyPair.getPrivate());
    assertNotNull(keyPair.getPublic());
    
    // Verify algorithm names
    assertEquals(paramSet, keyPair.getPrivate().getAlgorithm());
    assertEquals(paramSet, keyPair.getPublic().getAlgorithm());
    
    // Verify key types
    assertTrue(keyPair.getPrivate() instanceof EvpKemPrivateKey, 
               "Private key should be EvpKemPrivateKey");
    assertTrue(keyPair.getPublic() instanceof EvpKemPublicKey, 
               "Public key should be EvpKemPublicKey");
  }

  @Test
  public void testKeyFactorySelfConversion() throws Exception {
    for (String paramSet : new String[] {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"}) {
      KeyPairGenerator keyGen = KeyPairGenerator.getInstance(paramSet, NATIVE_PROVIDER);
      KeyPair originalKeyPair = keyGen.generateKeyPair();

      KeyFactory keyFactory = KeyFactory.getInstance("ML-KEM", NATIVE_PROVIDER);

      // Test public key round-trip
      byte[] publicKeyEncoded = originalKeyPair.getPublic().getEncoded();
      PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyEncoded));
      assertArrayEquals(publicKeyEncoded, publicKey.getEncoded());

      // Test private key round-trip  
      byte[] privateKeyEncoded = originalKeyPair.getPrivate().getEncoded();
      PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyEncoded));
      assertArrayEquals(privateKeyEncoded, privateKey.getEncoded());
    }
  }

  @Test
  public void testCrossProviderKeyFactoryAccess() throws Exception {
    // Test that all parameter-specific key factory lookups work
    KeyFactory kf512 = KeyFactory.getInstance("ML-KEM-512", NATIVE_PROVIDER);
    KeyFactory kf768 = KeyFactory.getInstance("ML-KEM-768", NATIVE_PROVIDER);
    KeyFactory kf1024 = KeyFactory.getInstance("ML-KEM-1024", NATIVE_PROVIDER);
    KeyFactory kfGeneric = KeyFactory.getInstance("ML-KEM", NATIVE_PROVIDER);
    
    assertNotNull(kf512);
    assertNotNull(kf768);
    assertNotNull(kf1024);
    assertNotNull(kfGeneric);
  }

  @Test
  public void testInvalidKeyInitialization() {
    assertThrows(
        InvalidKeyException.class,
        () -> {
          KeyPair rsaKeys = KeyPairGenerator.getInstance("RSA").generateKeyPair();
          KEM kem = KEM.getInstance("ML-KEM-512", NATIVE_PROVIDER);
          kem.newEncapsulator(rsaKeys.getPublic());
        });
  }

  @Test
  public void testBouncyCastleCompatibility() throws Exception {
    // Test encoding compatibility between ACCP and BC
    for (String paramSet : new String[] {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"}) {
      KeyPair nativePair = KeyPairGenerator.getInstance(paramSet, NATIVE_PROVIDER).generateKeyPair();
      PublicKey nativePub = nativePair.getPublic();
      PrivateKey nativePriv = nativePair.getPrivate();
      
      // Convert to BC
      KeyFactory bcKf = KeyFactory.getInstance("ML-KEM", TestUtil.BC_PROVIDER);
      PublicKey bcPub = bcKf.generatePublic(new X509EncodedKeySpec(nativePub.getEncoded()));
      PrivateKey bcPriv = bcKf.generatePrivate(new PKCS8EncodedKeySpec(nativePriv.getEncoded()));
      
      // Verify encoding compatibility
      TestUtil.assertArraysHexEquals(bcPub.getEncoded(), nativePub.getEncoded());
      assertEquals(bcPriv.getEncoded().length, nativePriv.getEncoded().length);
      TestUtil.assertArraysHexEquals(bcPriv.getEncoded(), nativePriv.getEncoded());
    }
  }

  @Test
  public void testParameterSetValidation() throws Exception {
    // Test that parameter sets are correctly identified and validated
    KeyPair pair512 = KeyPairGenerator.getInstance("ML-KEM-512", NATIVE_PROVIDER).generateKeyPair();
    KeyPair pair768 = KeyPairGenerator.getInstance("ML-KEM-768", NATIVE_PROVIDER).generateKeyPair();
    KeyPair pair1024 = KeyPairGenerator.getInstance("ML-KEM-1024", NATIVE_PROVIDER).generateKeyPair();
    
    // Verify parameter sets
    EvpKemPublicKey pub512 = (EvpKemPublicKey) pair512.getPublic();
    EvpKemPublicKey pub768 = (EvpKemPublicKey) pair768.getPublic();
    EvpKemPublicKey pub1024 = (EvpKemPublicKey) pair1024.getPublic();
    
    assertEquals(512, pub512.getParameterSet());
    assertEquals(768, pub768.getParameterSet());
    assertEquals(1024, pub1024.getParameterSet());
    
    // Verify algorithm names match parameter sets
    assertEquals("ML-KEM-512", pub512.getAlgorithm());
    assertEquals("ML-KEM-768", pub768.getAlgorithm());
    assertEquals("ML-KEM-1024", pub1024.getAlgorithm());
  }

  @Test
  public void testCiphertextSizes() throws Exception {
    // Verify ciphertext sizes match expected values
    String[] paramSets = {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"};
    int[] expectedSizes = {768, 1088, 1568};
    
    for (int i = 0; i < paramSets.length; i++) {
      KeyPair pair = KeyPairGenerator.getInstance(paramSets[i], NATIVE_PROVIDER).generateKeyPair();
      KEM kem = KEM.getInstance(paramSets[i], NATIVE_PROVIDER);
      
      NamedParameterSpec paramSpec = new NamedParameterSpec(paramSets[i]);
      KEM.Encapsulator encapsulator = kem.newEncapsulator(pair.getPublic(), paramSpec, null);
      KEM.Encapsulated encapsulated = encapsulator.encapsulate();
      
      assertEquals(expectedSizes[i], encapsulated.encapsulation().length,
                   "Ciphertext size should match expected value for " + paramSets[i]);
    }
  }

  @Test
  public void testKeyFactoryAlgorithmNameHandling() throws Exception {
    // Test that key factory accepts various algorithm name formats
    KeyPair pair = KeyPairGenerator.getInstance("ML-KEM-512", NATIVE_PROVIDER).generateKeyPair();
    
    // These should all work with the same key factory implementation
    KeyFactory kf1 = KeyFactory.getInstance("ML-KEM", NATIVE_PROVIDER);
    KeyFactory kf2 = KeyFactory.getInstance("ML-KEM-512", NATIVE_PROVIDER);
    
    // Both should be able to handle the same encoded key
    byte[] pubEncoded = pair.getPublic().getEncoded();
    byte[] privEncoded = pair.getPrivate().getEncoded();
    
    PublicKey pub1 = kf1.generatePublic(new X509EncodedKeySpec(pubEncoded));
    PublicKey pub2 = kf2.generatePublic(new X509EncodedKeySpec(pubEncoded));
    
    PrivateKey priv1 = kf1.generatePrivate(new PKCS8EncodedKeySpec(privEncoded));
    PrivateKey priv2 = kf2.generatePrivate(new PKCS8EncodedKeySpec(privEncoded));
    
    assertArrayEquals(pub1.getEncoded(), pub2.getEncoded());
    assertArrayEquals(priv1.getEncoded(), priv2.getEncoded());
  }
}