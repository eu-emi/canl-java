/*
 * Copyright (c) 2011 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.impl;

import static org.junit.Assert.*;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.DSAParameterSpec;

import org.junit.Assert;

import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.jce.ECGOST3410NamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.GOST3410ParameterSpec;
import org.junit.Test;

import eu.emi.security.authn.x509.X509Credential;
import eu.emi.security.authn.x509.helpers.CertificateHelpers;
import eu.emi.security.authn.x509.impl.CertificateUtils.Encoding;

public class CredentialsTest
{
	@Test
	public void testEmptyFiles()
	{
		try
		{
			new PEMCredential(CertificateUtilsTest.PFX + "empty.pem", CertificateUtilsTest.PFX + "cert-1.pem",
					CertificateUtilsTest.KS_P);
		} catch (IOException e)
		{
			//OK, expected
		} catch (Exception e)
		{
			e.printStackTrace();
			fail(e.toString());
		}
	}
	
	
	@Test
	public void testPEMKs() throws Exception
	{
		X509Credential cred = new PEMCredential(CertificateUtilsTest.PFX + 
				"keystore-1.pem", CertificateUtilsTest.KS_P);
		verifyCred(cred);
	}

	@Test
	public void testPEMSimple() throws Exception
	{
		X509Credential cred = new PEMCredential(
				CertificateUtilsTest.PFX + "pk-1.pem", 
				CertificateUtilsTest.PFX + "cert-1.pem",
				CertificateUtilsTest.KS_P);
		verifyCred(cred);
		
		X509Credential cred2 = new PEMCredential(
				CertificateUtilsTest.PFX + "pk-1.pem", 
				CertificateUtilsTest.PFX + "certAndCa.pem",
				CertificateUtilsTest.KS_P);
		verifyCred(cred2);
		assertEquals(2, cred2.getKeyStore().getCertificateChain(cred.getKeyAlias()).length);

		X509Credential cred3 = new PEMCredential(
				new FileReader(CertificateUtilsTest.PFX + "pk-1.pem"), 
				new FileReader(CertificateUtilsTest.PFX + "cert-1.pem"),
				CertificateUtilsTest.KS_P);
		verifyCred(cred3);
		
		X509Credential cred4 = new PEMCredential(
				CertificateUtilsTest.PFX + "pk-1.pem", 
				CertificateUtilsTest.PFX + "certAndCaReversed.pem",
				CertificateUtilsTest.KS_P);
		verifyCred(cred4);
		assertEquals(2, cred4.getKeyStore().getCertificateChain(cred.getKeyAlias()).length);
	}
	
	@Test
	public void testDER() throws Exception
	{
		X509Credential cred = new DERCredential(
				CertificateUtilsTest.PFX + "pk-1.der", 
				CertificateUtilsTest.PFX + "cert-1.der",
				CertificateUtilsTest.KS_P);
		verifyCred(cred);
	}
	
	
	@Test
	public void testKeyAndCertCredential() throws Exception
	{
		X509Certificate[] certs = CertificateUtils.loadCertificateChain(
				new FileInputStream(CertificateUtilsTest.PFX + "cert-1.pem"), 
				Encoding.PEM);
		PrivateKey pk = CertificateUtils.loadPrivateKey(
				new FileInputStream(CertificateUtilsTest.PFX + "pk-1.pem"), 
				Encoding.PEM,
				CertificateUtilsTest.KS_P);
		X509Credential cred = new KeyAndCertCredential(pk, certs);
		verifyCred(cred);
	}
	
	@Test
	public void testKeystoreCredential() throws Exception
	{
		X509Credential cred = new KeystoreCredential("src/test/resources/keystore-1.jks",
				CertificateUtilsTest.KS_P, CertificateUtilsTest.KS_P, 
				"mykey", "JKS");
		verifyCred(cred);

		X509Credential cred2 = new KeystoreCredential("src/test/resources/keystore-1.p12",
				CertificateUtilsTest.KS_P, CertificateUtilsTest.KS_P, 
				"mykey", "PKCS12");
		verifyCred(cred2);
	}

	@Test
	public void testAliasAutodetection() throws Exception
	{
		X509Credential cred = new KeystoreCredential("src/test/resources/keystore-1.jks",
				CertificateUtilsTest.KS_P, CertificateUtilsTest.KS_P, 
				null, "JKS");
		verifyCred(cred);

		X509Credential cred2 = new KeystoreCredential("src/test/resources/keystore-1.p12",
				CertificateUtilsTest.KS_P, CertificateUtilsTest.KS_P, 
				null, "PKCS12");
		verifyCred(cred2);
	}

	@Test
	public void testTypeAutodetection() throws Exception
	{
		String type = KeystoreCredential.autodetectType("src/test/resources/keystore-1.jks",
				CertificateUtilsTest.KS_P);
		assertEquals("JKS", type);

		type = KeystoreCredential.autodetectType("src/test/resources/keystore-1.p12",
				CertificateUtilsTest.KS_P);
		assertEquals("PKCS12", type);
	}
	
	private void verifyCred(X509Credential cred) throws Exception
	{
		assertNotNull(cred.getKeyManager());
		KeyStore ks = cred.getKeyStore();
		assertNotNull(ks);
		assertNotNull(ks.getKey(cred.getKeyAlias(), cred.getKeyPassword()));
		assertNotNull(ks.getCertificateChain(cred.getKeyAlias()));
	}

	@Test
	public void testInvalidParameters() 
	{
		try
		{
			new PEMCredential(
				CertificateUtilsTest.PFX + "pk-nonExisting.pem", 
				CertificateUtilsTest.PFX + "cert-1.pem",
				CertificateUtilsTest.KS_P);
			Assert.fail("Creation of credential with not existing file suceeded");
		} catch (FileNotFoundException e)
		{
			//expected
		} catch (Exception e)
		{
			Assert.fail("Wrong exception, instead of missing file " + e.toString());
		}
		
		try
		{
			new PEMCredential(
				CertificateUtilsTest.PFX + "pk-1.pem", 
				"src/test/resources/ca-v1/usercert.pem",
				CertificateUtilsTest.KS_P).getKeyStore();
			Assert.fail("Creation of credential with pk not matching certificate suceeded");
		} catch (KeyStoreException e)
		{
			Assert.assertTrue(e.toString(), e.getMessage().contains("matching"));
		} catch (Exception e)
		{
			Assert.fail("Wrong exception " + e.toString());
		}

		try
		{
			new PEMCredential(
				"src/test/resources/ca-v1/usercert.pem",
				CertificateUtilsTest.KS_P).getKeyStore();
			Assert.fail("Creation of pem-store credential without pk suceeded");
		} catch (IOException e)
		{
			Assert.assertTrue(e.toString(), e.getMessage().contains("key was not found"));
		} catch (Exception e)
		{
			e.printStackTrace();
			Assert.fail("Wrong exception " + e.toString());
		}
	}

	@Test
	public void testWrongPassword() 
	{

		try
		{
			new KeystoreCredential("src/test/resources/keystore-1.jks",
					"wrong".toCharArray(), CertificateUtilsTest.KS_P, 
					"mykey", "JKS");
			Assert.fail("Creation of jks credential with wrong ks password suceeded");
		}catch (Exception e)
		{
			assertTrue(e.getMessage().contains("password"));
		}

		try
		{
			new KeystoreCredential("src/test/resources/keystore-1.jks",
					CertificateUtilsTest.KS_P, "wrong".toCharArray(),  
					"mykey", "JKS");
			Assert.fail("Creation of ks credential with wrong ks-key password suceeded");
		}catch (Exception e)
		{
			assertTrue(e.getMessage().contains("password"));
		}
		
		try
		{
			new KeystoreCredential("src/test/resources/keystore-1.p12",
					"wrong".toCharArray(), CertificateUtilsTest.KS_P, 
					"mykey", "PKCS12");
			Assert.fail("Creation of pkcs12 credential with wrong password suceeded");
		} catch (Exception e)
		{
			assertTrue(e.toString(), e.getMessage().contains("password"));
		}
		
		try
		{
			new PEMCredential(
				CertificateUtilsTest.PFX + "pk-1.pem", 
				CertificateUtilsTest.PFX + "cert-1.pem",
				"wrong".toCharArray());
			Assert.fail("Creation of pem pair credential with wrong password suceeded");
		}catch (Exception e)
		{
			assertTrue(e.getMessage().contains("password"));
		}
		
		try
		{
			new PEMCredential(CertificateUtilsTest.PFX + 
					"keystore-1.pem", "wrong".toCharArray());
			Assert.fail("Creation of pem-store credential with wrong password suceeded");
		} catch (Exception e)
		{
			assertTrue(e.getMessage().contains("password"));
		}
		
		try
		{
			new DERCredential(
					CertificateUtilsTest.PFX + "pk-1.der", 
					CertificateUtilsTest.PFX + "cert-1.der",
					"wrong".toCharArray());
			Assert.fail("Creation of der credential with wrong password suceeded");
		} catch (Exception e)
		{
			assertTrue(e.getMessage().contains("password"));
		}
	}

	
	@Test
	public void testNotMatchingKeys() throws Exception
	{
		Security.addProvider(new BouncyCastleProvider());
		
		SecureRandom rand = SecureRandom.getInstance("SHA1PRNG");
		rand.setSeed(System.currentTimeMillis());
		

		KeyPairGenerator kpg  = KeyPairGenerator.getInstance("RSA", "BC");
		kpg.initialize(256, rand);
		KeyPair rsaKp1 = kpg.generateKeyPair();
		KeyPair rsaKp2 = kpg.generateKeyPair();
		verify(rsaKp1, rsaKp2);

		KeyPairGenerator dsaKpg = KeyPairGenerator.getInstance("DSA", "BC");
		DSAParameterSpec dsaSpec = new DSAParameterSpec(
			new BigInteger("7434410770759874867539421675728577177024889699586189000788950934679315164676852047058354758883833299702695428196962057871264685291775577130504050839126673"),
			new BigInteger("1138656671590261728308283492178581223478058193247"),
			new BigInteger("4182906737723181805517018315469082619513954319976782448649747742951189003482834321192692620856488639629011570381138542789803819092529658402611668375788410"));
		dsaKpg.initialize(dsaSpec, rand);
		KeyPair dsaKp1 = dsaKpg.generateKeyPair();
		KeyPair dsaKp2 = dsaKpg.generateKeyPair();
		verify(dsaKp1, dsaKp2);

				
		KeyPairGenerator gostKpg  = KeyPairGenerator.getInstance("GOST3410", "BC");
		GOST3410ParameterSpec gost3410P = new GOST3410ParameterSpec(
			CryptoProObjectIdentifiers.gostR3410_94_CryptoPro_A.getId());
		gostKpg.initialize(gost3410P, rand);
		KeyPair gostKp1 = gostKpg.generateKeyPair();
		KeyPair gostKp2 = gostKpg.generateKeyPair();
		verify(gostKp1, gostKp2);
		
		KeyPairGenerator ecGostKpg = KeyPairGenerator.getInstance("ECGOST3410", "BC");
		ecGostKpg.initialize(ECGOST3410NamedCurveTable.getParameterSpec(
			"GostR3410-2001-CryptoPro-A"), rand);
		KeyPair ecGostKp1 = ecGostKpg.generateKeyPair();
		KeyPair ecGostKp2 = ecGostKpg.generateKeyPair();
		verify(ecGostKp1, ecGostKp2);
		
		KeyPairGenerator ecDsaKpg = KeyPairGenerator.getInstance("ECDSA", "BC");
		ecDsaKpg.initialize(239, rand);
		KeyPair ecDsaKp1 = ecDsaKpg.generateKeyPair();
		KeyPair ecDsaKp2 = ecDsaKpg.generateKeyPair();
		verify(ecDsaKp1, ecDsaKp2);

	}
	
	private void verify(KeyPair kp1, KeyPair kp2)
	{
		try
		{
			CertificateHelpers.checkKeysMatching(kp1.getPrivate(), kp2.getPublic());
			Assert.fail("not matching keys assumed to be not matching: " + kp1.getPublic());
		} catch (InvalidKeyException e)
		{
			//expected
		}
		try
		{
			CertificateHelpers.checkKeysMatching(kp2.getPrivate(), kp1.getPublic());
			Assert.fail("not matching keys assumed to be matching (2) " + kp1.getPublic());
		} catch (InvalidKeyException e)
		{
			//expected
		}
		
		try
		{
			CertificateHelpers.checkKeysMatching(kp1.getPrivate(), kp1.getPublic());
			CertificateHelpers.checkKeysMatching(kp1.getPrivate(), kp1.getPublic());
		} catch (InvalidKeyException e)
		{
			Assert.fail("matching keys assumed to be not matching: " + e.toString());
		}
	}
}



