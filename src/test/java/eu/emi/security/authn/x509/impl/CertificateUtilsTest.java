/*
 * Copyright (c) 2011 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.impl;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPrivateKey;

import static org.junit.Assert.*;

import org.bouncycastle.openssl.PKCS8Generator;
import org.junit.Test;

import eu.emi.security.authn.x509.X509Credential;
import eu.emi.security.authn.x509.impl.CertificateUtils.Encoding;

public class CertificateUtilsTest
{
	public static final String PFX = "src/test/resources/test-pems/";
	public static final char[] KEY_P = "the!key".toCharArray();
	public static final char[] KS_P = "the!njs".toCharArray();
	
	@Test
	public void testLegacyKeys() throws Exception
	{
		X509Credential cred = new PEMCredential("src/test/resources/test-pems/keystore-1-legacy.pem", "the!njs".toCharArray());
		assertNotNull(cred.getKey());
		
		InputStream is = new FileInputStream("src/test/resources/test-pems/pk-1-legacy-unencrypted.pem");
		PrivateKey pk = CertificateUtils.loadPrivateKey(is, Encoding.PEM, null);
		assertNotNull(pk);
		
		is = new FileInputStream("src/test/resources/test-pems/pk-1-legacy-encrypted.pem");
		assertNotNull(CertificateUtils.loadPrivateKey(is, Encoding.PEM, "the!njs".toCharArray()));
		
		ByteArrayOutputStream os = new ByteArrayOutputStream();
		CertificateUtils.savePrivateKey(os, pk, Encoding.PEM, "AES-256-CBC",
				"the!njs".toCharArray(), true);

		ByteArrayInputStream is2 = new ByteArrayInputStream(os.toByteArray());
		pk = CertificateUtils.loadPrivateKey(is2, Encoding.PEM, "the!njs".toCharArray());
		assertNotNull(pk);
	}
	
	
	

	@Test
	public void testEmptySubject() throws Exception
	{
		X509Certificate cert = CertificateUtils.loadCertificate(
				new FileInputStream("src/test/resources/NIST/certs/ValidDNnameConstraintsTest14EE.crt"), 
				Encoding.DER);
		assertTrue(CertificateUtils.format(cert, FormatMode.COMPACT_ONE_LINE).contains("Subject: ,"));
	}
	
	@Test
	public void testConvert() throws Exception
	{
		X509Certificate cert = CertificateUtils.loadCertificate(
				new FileInputStream(PFX + "cacert.pem"), 
				Encoding.PEM);
		System.out.println(cert.getSigAlgOID());
		System.out.println(cert.getSigAlgName());
		assertEquals(1, CertificateUtils.convertToX509Chain(
				new Certificate[] {cert}).length);
		assertEquals(0,	CertificateUtils.convertToX509Chain(
				new Certificate[0]).length);
	}
	
	@Test
	public void testLoadPemCert() throws Exception
	{
		X509Certificate cert = CertificateUtils.loadCertificate(
				new FileInputStream(PFX + "cacert.pem"), 
				Encoding.PEM);
		assertEquals("CN=UNICORE TEST CA,O=Testing Organization,C=EU", 
				X500NameUtils.getReadableForm(cert.getSubjectX500Principal()));
		
		cert = CertificateUtils.loadCertificate(
				new FileInputStream(PFX + "certAndCa.pem"), 
				Encoding.PEM);
		assertEquals("CN=PDPTest Server,O=Testing Organization,L=Testing City,C=EU", 
				X500NameUtils.getReadableForm(cert.getSubjectX500Principal()));
		
	}
		
	
	@Test
	public void testLoadPK() throws Exception
	{
		String [] keys = {"dsa-1024-3des-p8.pem", 
				"ec-prime192v1-3des-p8.pem",
				"rsa-4096-plain-p8.pem",
				"dsa-1024-plain-p8.pem", 
				"ec-prime192v1-plain-p8.pem",
				"rsa-4096-3des-p8.pem",
				
				"dsa-1024-3des-p8.der", 
				"ec-prime192v1-3des-p8.der",
				"rsa-4096-plain-p8.der",
				"dsa-1024-plain-p8.der", 
				"ec-prime192v1-plain-p8.der",
				"rsa-4096-3des-p8.der",
				
				"key-src/dsa-1024-3des.pem",
				"key-src/dsa-1024-plain.pem",
				"key-src/ec-prime192v1-des.pem",
				"key-src/ec-prime192v1-plain.pem",
				"key-src/rsa-128-3des.pem",
				"key-src/rsa-4096-aes256.pem",
				"key-src/rsa-4096-plain.pem"
				};
		for (String key: keys)
		{
			char []pass = key.contains("plain") ? null : KEY_P;
			Encoding enc = key.contains(".der") ? Encoding.DER : Encoding.PEM;
			try
			{
				CertificateUtils.loadPrivateKey(
					new FileInputStream(PFX + "keys/" + key),
					enc, pass);
			} catch (IOException e)
			{
				e.printStackTrace();
				fail("Error readding PK " + key + ": " + e);
			}
		}
	}
	
	@Test
	public void loadPEMKeystore() throws Exception
	{
		for (int i=1; i<5; i++)
		{
			KeyStore ks = CertificateUtils.loadPEMKeystore(new FileInputStream(
					PFX + "keystore-" + i + ".pem"), KS_P, KS_P);
			checkKS(ks);
		}
	}
	
	private void checkKS(KeyStore ks) throws Exception
	{
		assertTrue(ks.isKeyEntry(CertificateUtils.DEFAULT_KEYSTORE_ALIAS));
		Certificate[] chain = ks.getCertificateChain(
				CertificateUtils.DEFAULT_KEYSTORE_ALIAS);
		assertEquals(2, chain.length);
		X509Certificate []chainX = CertificateUtils.convertToX509Chain(chain);
		assertEquals(chainX[0].getIssuerX500Principal(), 
				chainX[1].getSubjectX500Principal());
	}
	
	@Test
	public void loadSavePemKeystore() throws Exception
	{
		KeyStore ks = CertificateUtils.loadPEMKeystore(new FileInputStream(
				PFX + "keystore-1.pem"), KS_P, KS_P);
		ByteArrayOutputStream os = new ByteArrayOutputStream();
		
		CertificateUtils.savePEMKeystore(os, ks, CertificateUtils.DEFAULT_KEYSTORE_ALIAS,
				null, KS_P, KS_P);
		KeyStore ks2 = CertificateUtils.loadPEMKeystore(new ByteArrayInputStream(
				os.toByteArray()), (char[])null, KS_P);
		checkKS(ks2);

		os.reset();
		
		CertificateUtils.savePEMKeystore(os, ks, CertificateUtils.DEFAULT_KEYSTORE_ALIAS,
				PKCS8Generator.AES_192_CBC.getId(), KS_P, KS_P);
		
		KeyStore ks3 = CertificateUtils.loadPEMKeystore(new ByteArrayInputStream(
				os.toByteArray()), KS_P, KS_P);
		checkKS(ks3);
		
		try
		{
			CertificateUtils.savePEMKeystore(os, ks, CertificateUtils.DEFAULT_KEYSTORE_ALIAS,
				"WRONG!", KS_P, KS_P);
			fail("should get IllaegalArgumentException");
		} catch (IllegalArgumentException ile)
		{
			//OK!
		} catch (Exception e)
		{
			fail("should get IllegalArgumentException, not " + e);			
		}
		
		
		KeyStore ks4 = CertificateUtils.loadPEMKeystore(new FileInputStream(
				PFX + "keystore-1.pem"), KS_P, KS_P);
		ByteArrayOutputStream os2 = new ByteArrayOutputStream();
		
		CertificateUtils.savePEMKeystore(os2, ks4, CertificateUtils.DEFAULT_KEYSTORE_ALIAS,
				null, KS_P, null);
		System.out.println(os2.toString());
		KeyStore ks5 = CertificateUtils.loadPEMKeystore(new ByteArrayInputStream(
				os2.toByteArray()), (char[])null, KS_P);
		checkKS(ks5);

	}
	
	@Test
	public void loadSavePK() throws Exception
	{
		try
		{
			PrivateKey pk = CertificateUtils.loadPrivateKey(
				new FileInputStream(PFX + "keys/" + "dsa-1024-3des-p8.pem"),
				Encoding.PEM, KEY_P);
			System.out.println(((DSAPrivateKey)pk).getParams().getG().bitLength());
			
			
			ByteArrayOutputStream os = new ByteArrayOutputStream();			
			CertificateUtils.savePrivateKey(os, pk, Encoding.PEM, 
					PKCS8Generator.DES3_CBC.getId(), KEY_P);
			PrivateKey pk2 = CertificateUtils.loadPrivateKey(
					new ByteArrayInputStream(os.toByteArray()),
					Encoding.PEM, KEY_P);
			assertTrue(pk.equals(pk2));
			
			os.reset();
			CertificateUtils.savePrivateKey(os, pk, Encoding.DER, 
					PKCS8Generator.AES_192_CBC.getId(), KEY_P);
			PrivateKey pk3 = CertificateUtils.loadPrivateKey(
					new ByteArrayInputStream(os.toByteArray()),
					Encoding.DER, KEY_P);
			assertTrue(pk.equals(pk3));

			os.reset();
			CertificateUtils.savePrivateKey(os, pk, Encoding.DER, 
					null, null);
			PrivateKey pk4 = CertificateUtils.loadPrivateKey(
					new ByteArrayInputStream(os.toByteArray()),
					Encoding.DER, null);
			assertTrue(pk.equals(pk4));

			os.reset();
			CertificateUtils.savePrivateKey(os, pk, Encoding.PEM, 
					null, null);
			PrivateKey pk5 = CertificateUtils.loadPrivateKey(
					new ByteArrayInputStream(os.toByteArray()),
					Encoding.PEM, null);
			
			assertTrue(pk.equals(pk5));
		
		} catch (IOException e)
		{
			e.printStackTrace();
			fail("Error readding PK: " + e);
		}
	}

	@Test
	public void loadSaveCert() throws Exception
	{
		X509Certificate cert = CertificateUtils.loadCertificate(
				new FileInputStream(PFX + "cacert.pem"), 
				Encoding.PEM);
		ByteArrayOutputStream os = new ByteArrayOutputStream();
		CertificateUtils.saveCertificate(os, cert, Encoding.PEM);
		X509Certificate cert1 = CertificateUtils.loadCertificate(new ByteArrayInputStream(os.toByteArray()), 
				Encoding.PEM);
		assertEquals(cert.getSubjectX500Principal(), cert1.getSubjectX500Principal());
		
		os.reset();
		CertificateUtils.saveCertificate(os, cert, Encoding.DER);
		X509Certificate cert2 = CertificateUtils.loadCertificate(new ByteArrayInputStream(os.toByteArray()), 
				Encoding.DER);
		assertEquals(cert.getSubjectX500Principal(), cert2.getSubjectX500Principal());
	}

	@Test
	public void loadSaveCertChain() throws Exception
	{
		X509Certificate[] certChain = new X509Certificate[2];
		certChain[0] = CertificateUtils.loadCertificate(
				new FileInputStream(PFX + "cert-1.pem"), 
				Encoding.PEM);
		certChain[1] = CertificateUtils.loadCertificate(
				new FileInputStream(PFX + "cacert.pem"), 
				Encoding.PEM);
		
		ByteArrayOutputStream os = new ByteArrayOutputStream();
		CertificateUtils.saveCertificateChain(os, certChain, Encoding.PEM);
		X509Certificate[] certChain2 = CertificateUtils.loadCertificateChain(
				new ByteArrayInputStream(os.toByteArray()), Encoding.PEM);
		assertEquals(certChain[0].getSubjectX500Principal(), 
				certChain2[0].getSubjectX500Principal());
		assertEquals(certChain[1].getSubjectX500Principal(), 
				certChain2[1].getSubjectX500Principal());
		
		String str = new String(os.toByteArray());
		assertTrue(str.startsWith("-----BEGIN CERTIFICATE"));
		assertTrue(str.indexOf("-----BEGIN CERTIFICATE", 10) != -1);
		os.reset();

		CertificateUtils.saveCertificateChain(os, certChain, Encoding.DER);
		X509Certificate[] certChain3 = CertificateUtils.loadCertificateChain(
				new ByteArrayInputStream(os.toByteArray()), Encoding.DER);
		assertEquals(certChain[0].getSubjectX500Principal(), 
				certChain3[0].getSubjectX500Principal());
		assertEquals(certChain[1].getSubjectX500Principal(), 
				certChain3[1].getSubjectX500Principal());
	}
	
	@Test
	public void certPrint() throws Exception
	{
		X509Certificate cert = CertificateUtils.loadCertificate(
				new FileInputStream(PFX + "cacert.pem"), 
				Encoding.PEM);
		System.out.println("-------------------COMPACT");
		System.out.println(CertificateUtils.format(cert, FormatMode.COMPACT));
		System.out.println("-------------------");
		System.out.println(CertificateUtils.format(cert, FormatMode.COMPACT_ONE_LINE));
		System.out.println("\n-------------------MEDIUM");
		System.out.println(CertificateUtils.format(cert, FormatMode.MEDIUM));
		System.out.println("-------------------");
		System.out.println(CertificateUtils.format(cert, FormatMode.MEDIUM_ONE_LINE));
		System.out.println("\n-------------------FULL");
		System.out.println(CertificateUtils.format(cert, FormatMode.FULL));
		
		System.out.println(CertificateUtils.format(new X509Certificate[] 
				{cert, cert, cert}, 
				FormatMode.MEDIUM));
		
	}
}




