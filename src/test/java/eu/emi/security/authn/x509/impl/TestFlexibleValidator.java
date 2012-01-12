/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.impl;

import static org.junit.Assert.*;

import java.io.File;
import java.io.FileInputStream;
import java.security.cert.X509Certificate;
import java.util.Collections;

import org.apache.commons.io.FileUtils;
import org.junit.Test;

import eu.emi.security.authn.x509.CrlCheckingMode;
import eu.emi.security.authn.x509.RevocationCheckingMode;
import eu.emi.security.authn.x509.StoreUpdateListener;
import eu.emi.security.authn.x509.ValidationResult;
import eu.emi.security.authn.x509.impl.CertificateUtils.Encoding;

public class TestFlexibleValidator
{
	private int error;
	
	@Test
	public void testValidator() throws Exception
	{
		DirectoryCertChainValidator validator1 = new DirectoryCertChainValidator(
				Collections.singletonList("src/test/resources/truststores/*.pem"), 
				new CRLParameters(), new RevocationCheckingMode(CrlCheckingMode.IGNORE), 
				-1, 5000, null, false);
		
		X509Certificate[] toValidate = CertificateUtils.loadCertificateChain(
				new FileInputStream("src/test/resources/validator-certs/trusted_client.cert"), 
				Encoding.PEM);
		
		ValidationResult res = validator1.validate(toValidate);
		assertTrue(res.isValid());
		
		assertEquals(1, validator1.getTruststorePaths().size());
		validator1.dispose();
	}
	
	@Test
	public void testUpdate() throws Exception
	{
		File dir = TestKSValidators.initDir();
		DirectoryCertChainValidator validator1 = new DirectoryCertChainValidator(
				Collections.singletonList(dir.getPath() + "/*.pem"), 
				new CRLParameters(), new RevocationCheckingMode(CrlCheckingMode.IGNORE), 
				-1, 5000, null, false);
		
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
		
		validator1.setTruststoreUpdateInterval(200);
		FileUtils.copyFileToDirectory(new File("src/test/resources/truststores/trustedMain.pem"), dir);
		Thread.sleep(500);
		ValidationResult res2 = validator1.validate(toValidate);
		assertTrue(res2.isValid());
		assertEquals(0, error);

		new File(dir, "trustedMain.pem").delete();
		Thread.sleep(500);
		ValidationResult res3 = validator1.validate(toValidate);
		assertFalse(res3.isValid());
		assertEquals(0, error);

		new File(dir, "wrong.pem").createNewFile();
		Thread.sleep(500);
		assertTrue(1 <= error);
		
		validator1.dispose();
	}

}
