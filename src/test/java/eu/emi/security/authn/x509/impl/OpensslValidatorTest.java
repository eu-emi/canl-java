/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.impl;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.util.Collections;

import org.junit.Assert;

import org.junit.Test;

import eu.emi.security.authn.x509.CrlCheckingMode;
import eu.emi.security.authn.x509.NamespaceCheckingMode;
import eu.emi.security.authn.x509.OCSPCheckingMode;
import eu.emi.security.authn.x509.OCSPParametes;
import eu.emi.security.authn.x509.ProxySupport;
import eu.emi.security.authn.x509.RevocationParameters;
import eu.emi.security.authn.x509.StoreUpdateListener;
import eu.emi.security.authn.x509.ValidationResult;
import eu.emi.security.authn.x509.impl.CertificateUtils.Encoding;


public class OpensslValidatorTest
{
	@Test
	public void testValidator() throws Exception
	{
		ValidatorParamsExt params = new ValidatorParamsExt();
		params.setInitialListeners(Collections.singleton(new StoreUpdateListener()
		{
			@Override
			public void loadingNotification(String location, String type, Severity level,
					Exception cause)
			{
				System.out.println(level + " " + type + " location: " + location + " cause: " + cause);
				if (cause != null && level != Severity.NOTIFICATION) {
					cause.printStackTrace();
					Assert.fail("Got error");
				}
			}
		}));
		OpensslCertChainValidator validator1 = new OpensslCertChainValidator(
				"src/test/resources/glite-utiljava/grid-security/certificates-newhash",
				true,
				NamespaceCheckingMode.EUGRIDPMA_GLOBUS, -1, 
				params);
		X509Certificate[] cert = CertificateUtils.loadCertificateChain(new FileInputStream("src/test/resources/glite-utiljava/slash-certs/slash_client_slash.cert"), Encoding.PEM);
		ValidationResult result = validator1.validate(cert);
		Assert.assertTrue(result.toString(), result.isValid());

		X509Certificate[] cert2 = CertificateUtils.loadCertificateChain(new FileInputStream("src/test/resources/glite-utiljava/subsubca-certs/subsubca_client_slash.cert"), Encoding.PEM);
		ValidationResult result2 = validator1.validate(cert2);
		Assert.assertTrue(result2.toString(), result2.isValid());
		validator1.dispose();
	}
	
	@Test
	public void testValidatorNoCRL() throws Exception
	{
		OpensslCertChainValidator validator1 = new OpensslCertChainValidator(
				"src/test/resources/glite-utiljava/certificates-nocrl");
		X509Certificate[] cert = CertificateUtils.loadCertificateChain(new FileInputStream("src/test/resources/glite-utiljava/slash-certs/slash_client_slash.cert"), Encoding.PEM);
		ValidationResult result = validator1.validate(cert);
		Assert.assertTrue(result.toString(), result.isValid());

		X509Certificate[] cert2 = CertificateUtils.loadCertificateChain(new FileInputStream("src/test/resources/glite-utiljava/subsubca-certs/subsubca_client_slash.cert"), Encoding.PEM);
		ValidationResult result2 = validator1.validate(cert2);
		Assert.assertTrue(result2.toString(), result2.isValid());
		validator1.dispose();
	}
	
	@Test
	public void testExpiredWithCrl() throws Exception
	{
		RevocationParameters revocationParams = new RevocationParameters(CrlCheckingMode.REQUIRE, 
				new OCSPParametes(OCSPCheckingMode.IGNORE));
		OpensslCertChainValidator validator1 = new OpensslCertChainValidator(
				"src/test/resources/expired-and-crl/openssl-trustdir",
				NamespaceCheckingMode.EUGRIDPMA_GLOBUS, -1, 
				new ValidatorParams(revocationParams, ProxySupport.ALLOW));
		
		InputStream is = new FileInputStream("src/test/resources/test-pems/expiredcert.pem");
		X509Certificate[] certChain = CertificateUtils.loadCertificateChain(is, Encoding.PEM);
		ValidationResult result = validator1.validate(certChain);
		Assert.assertFalse("Expired certificate is valid", result.isValid());
		Assert.assertEquals("Other than two errors returned: " + result.toString(), 2, result.getErrors().size());
		Assert.assertTrue("Got wrong message (0): " + result.getErrors().get(0).toString(), 
				result.getErrors().get(0).getMessage().contains("expired"));
		Assert.assertTrue("Got wrong message (1): " + result.getErrors().get(1).toString(), 
				result.getErrors().get(1).getMessage().contains("expired"));
		
		validator1.dispose();
	}
}