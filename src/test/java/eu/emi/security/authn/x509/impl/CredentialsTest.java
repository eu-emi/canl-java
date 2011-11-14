/*
 * Copyright (c) 2011 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.impl;

import static junit.framework.Assert.*;

import java.io.FileInputStream;
import java.io.FileReader;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.junit.Test;

import eu.emi.security.authn.x509.X509Credential;
import eu.emi.security.authn.x509.impl.CertificateUtils.Encoding;

public class CredentialsTest
{
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
	
	private void verifyCred(X509Credential cred) throws Exception
	{
		assertNotNull(cred.getKeyManager());
		KeyStore ks = cred.getKeyStore();
		assertNotNull(ks);
		assertNotNull(ks.getKey(cred.getKeyAlias(), cred.getKeyPassword()));
		assertNotNull(ks.getCertificateChain(cred.getKeyAlias()));
	}
}
