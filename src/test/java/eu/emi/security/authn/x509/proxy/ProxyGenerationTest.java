/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.proxy;

import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;

import org.junit.Assert;
import org.junit.Test;

import eu.emi.security.authn.x509.X509Credential;
import eu.emi.security.authn.x509.impl.CertificateUtils;
import eu.emi.security.authn.x509.impl.CertificateUtilsTest;
import eu.emi.security.authn.x509.impl.KeystoreCredential;


public class ProxyGenerationTest
{
	@Test
	public void testDefaultLifetime() throws Exception
	{
		X509Credential credential = new KeystoreCredential("src/test/resources/keystore-1.jks",
				CertificateUtilsTest.KS_P, CertificateUtilsTest.KS_P, 
				"mykey", "JKS");
		PrivateKey privateKey = (PrivateKey) credential.getKeyStore().getKey(
				credential.getKeyAlias(), credential.getKeyPassword());
		Certificate c[] = credential.getKeyStore().getCertificateChain(credential.getKeyAlias());
		X509Certificate chain[] = CertificateUtils.convertToX509Chain(c);
		ProxyCertificateOptions param = new ProxyCertificateOptions(chain);
		
		Assert.assertEquals(param.getKeyLength(), 1024);
		ProxyCertificate proxy1 = ProxyGenerator.generate(param, privateKey);
		int bitLength = ((RSAPublicKey)proxy1.getCertificateChain()[0].getPublicKey()).
				getModulus().bitLength();
		Assert.assertEquals(1024, bitLength);
		

		param.setLifetime(3600000);
		ProxyCertificate proxy2 = ProxyGenerator.generate(param, privateKey);
		int bitLength2 = ((RSAPublicKey)proxy2.getCertificateChain()[0].getPublicKey()).
				getModulus().bitLength();
		Assert.assertEquals(2048, bitLength2);
	}
}
