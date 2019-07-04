/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.impl;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileInputStream;
import java.security.cert.X509Certificate;
import java.util.Collections;

import org.apache.commons.io.FileUtils;
import org.junit.Test;

import eu.emi.security.authn.x509.ProxySupport;
import eu.emi.security.authn.x509.StoreUpdateListener;
import eu.emi.security.authn.x509.ValidationResult;
import eu.emi.security.authn.x509.impl.CertificateUtils.Encoding;

public class DirectoryCertChainValidatorTest
{
	private int error;
	
	@Test
	public void testValidator() throws Exception
	{
		DirectoryCertChainValidator validator1 = new DirectoryCertChainValidator(
				Collections.singletonList("src/test/resources/truststores/*.pem"), Encoding.PEM,
				-1, 5000, null, new ValidatorParamsExt(
					RevocationParametersExt.IGNORE,
					ProxySupport.DENY));
		
		X509Certificate[] toValidate = CertificateUtils.loadCertificateChain(
				new FileInputStream("src/test/resources/validator-certs/trusted_client.cert"), 
				Encoding.PEM);
		
		ValidationResult res = validator1.validate(toValidate);
		assertTrue(res.isValid());
		
		assertEquals(1, validator1.getTruststorePaths().size());
		validator1.dispose();
	}
	
	@Test 
	public void twoCertificatesFromMultiPemAreTrusted() throws Exception
	{
		DirectoryCertChainValidator validator = new DirectoryCertChainValidator(
				Collections.singletonList("src/test/resources/truststores/multipem.pem"), Encoding.PEM,
				-1, 5000, null, new ValidatorParamsExt(
					RevocationParametersExt.IGNORE,
					ProxySupport.DENY));
		
		X509Certificate[] trustedIssuers = validator.getTrustedIssuers();
		
		assertThat(trustedIssuers.length, is(2));
	}
	
	@Test
	public void testUpdate() throws Exception
	{
		File dir = TestKSValidators.initDir();
		DirectoryCertChainValidator validator1 = new DirectoryCertChainValidator(
				Collections.singletonList(dir.getPath() + "/*.pem"), Encoding.PEM, 
				-1, 500000, null, new ValidatorParamsExt(
					RevocationParametersExt.IGNORE,	ProxySupport.DENY));
		
		X509Certificate[] toValidate = CertificateUtils.loadCertificateChain(
				new FileInputStream("src/test/resources/validator-certs/trusted_client.cert"), 
				Encoding.PEM);
		error = 0;
		validator1.addUpdateListener(new StoreUpdateListener()
		{
			@Override
			public void loadingNotification(String location, String type,
					Severity level, Exception cause)
			{
				assertEquals(StoreUpdateListener.CA_CERT, type);
				if (level != Severity.NOTIFICATION)
				{
					System.out.println(location + " " + cause);
					error++;
				}
			}
		});
		
		ValidationResult res = validator1.validate(toValidate);
		assertFalse(res.isValid());
		assertEquals(0, error);
		
		FileUtils.copyFileToDirectory(new File("src/test/resources/truststores/trustedMain.pem"), dir);
		validator1.trustStore.update();
		ValidationResult res2 = validator1.validate(toValidate);
		assertTrue(res2.isValid());
		assertEquals(0, error);

		new File(dir, "trustedMain.pem").delete();
		validator1.trustStore.update();
		ValidationResult res3 = validator1.validate(toValidate);
		assertFalse(res3.isValid());
		assertEquals(0, error);

		new File(dir, "wrong.pem").createNewFile();
		validator1.trustStore.update();
		assertTrue(1 <= error);
		
		validator1.dispose();
	}

	@Test
	public void shouldUpdateAnchorWhenContentsChangesButFilenameIsSame() throws Exception
	{
		File dir = TestKSValidators.initDir();
		File destPem = new File(dir, "fixed-name.pem");
		DirectoryCertChainValidator validator1 = new DirectoryCertChainValidator(
				Collections.singletonList(dir.getPath() + "/*.pem"), Encoding.PEM, 
				-1, 500000, null, new ValidatorParamsExt(
					RevocationParametersExt.IGNORE,	ProxySupport.DENY));
		
		X509Certificate[] toValidate = CertificateUtils.loadCertificateChain(
				new FileInputStream("src/test/resources/validator-certs/trusted_client.cert"), 
				Encoding.PEM);
		
		ValidationResult res = validator1.validate(toValidate);
		assertThat(res.isValid(), is(false));
		
		FileUtils.copyFile(new File("src/test/resources/test-pems/cert-1.pem"), destPem);
		validator1.trustStore.update();
		assertThat(res.isValid(), is(false));
		
		FileUtils.copyFile(new File("src/test/resources/truststores/trustedMain.pem"), destPem);
		validator1.trustStore.update();
		ValidationResult res2 = validator1.validate(toValidate);
		assertThat(res2.isValid(), is(true));
		assertThat(validator1.getTrustedIssuers().length, is(1));
		validator1.dispose();
	}
	
}
