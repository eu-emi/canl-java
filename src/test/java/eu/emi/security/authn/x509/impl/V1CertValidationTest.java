/*
 * Copyright (c) 2011 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.impl;

import java.io.FileInputStream;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import junit.framework.Assert;

import org.junit.Test;

import eu.emi.security.authn.x509.ValidationResult;
import eu.emi.security.authn.x509.X509Credential;
import eu.emi.security.authn.x509.impl.CertificateUtils.Encoding;
import eu.emi.security.authn.x509.proxy.ProxyCertificate;
import eu.emi.security.authn.x509.proxy.ProxyCertificateOptions;
import eu.emi.security.authn.x509.proxy.ProxyGenerator;

public class V1CertValidationTest
{
	@Test
	public void test() throws Exception
	{
		DirectoryCertChainValidator validator = new DirectoryCertChainValidator(
				"src/test/resources/ca-v1/cacert.pem", 
				"src/test/resources/ca-v1/*.crl", null);
		
		X509Certificate[] cert1 = CertificateUtils.loadCertificateChain(
				new FileInputStream("src/test/resources/ca-v1/usercert.pem"), 
				Encoding.PEM);
		
		ValidationResult result = validator.validate(cert1);
		Assert.assertTrue(result.toString(), result.isValid());
		
		X509Credential credential = new PEMCredential("src/test/resources/ca-v1/userkey.pem", 
				"src/test/resources/ca-v1/usercert.pem",
				"qwerty".toCharArray());
		Certificate c[] = credential.getKeyStore().getCertificateChain(credential.getKeyAlias());
		X509Certificate chain[] = CertificateUtils.convertToX509Chain(c);
		ProxyCertificateOptions param = new ProxyCertificateOptions(chain);
		PrivateKey privateKey = (PrivateKey) credential.getKeyStore().getKey(
				credential.getKeyAlias(), credential.getKeyPassword());
		
		ProxyCertificate proxy1 = ProxyGenerator.generate(param, privateKey);
		
		ValidationResult result2 = validator.validate(proxy1.getCertificateChain());
		Assert.assertTrue(result2.toString(), result2.isValid());
	}
}
