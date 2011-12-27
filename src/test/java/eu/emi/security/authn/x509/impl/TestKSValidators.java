/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.impl;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.cert.CertPath;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;

import static org.junit.Assert.*;

import org.apache.commons.io.FileUtils;
import org.junit.Test;

import eu.emi.security.authn.x509.ChainValidationError;
import eu.emi.security.authn.x509.StoreUpdateListener;
import eu.emi.security.authn.x509.ValidationErrorListener;
import eu.emi.security.authn.x509.ValidationResult;
import eu.emi.security.authn.x509.impl.CertificateUtils.Encoding;

/**
 * Testing of {@link InMemoryKeystoreCertChainValidator} and {@link KeystoreCertChainValidator}
 * is done here. The tests are in fact designed also to test all their parent classes
 * which provide a lot o shared functionality also for other validators.
 * 
 * @author K. Benedyczak
 */
public class TestKSValidators
{
	private boolean gotError;
	private int vError;
	
	public static File initDir() throws IOException
	{
		File dir = new File("target/test-tmp/truststores");
		FileUtils.deleteDirectory(dir);
		dir.mkdirs();
		return dir;
	}

	/**
	 * Tests creation, basic validation
	 */
	@Test
	public void testKeystoreValidator() throws Exception
	{
		String path = "src/test/resources/truststores/truststore1.jks";
		KeystoreCertChainValidator validator1 = new KeystoreCertChainValidator(
				path, "the!njs".toCharArray(), "JKS", 
				new CRLParameters(), CrlCheckingMode.IGNORE, -1, false);
		X509Certificate[] toValidate = CertificateUtils.loadCertificateChain(
				new FileInputStream("src/test/resources/validator-certs/trusted_client.cert"), 
				Encoding.PEM);
		
		CertificateFactory factory = CertificateFactory.getInstance("X.509");
		CertPath certPath = factory.generateCertPath(Arrays.asList(toValidate));
		
		ValidationResult res = validator1.validate(toValidate);
		assertTrue(res.isValid());
		
		ValidationResult res1 = validator1.validate(certPath);
		assertTrue(res1.isValid());
		
		assertEquals(validator1.getTruststorePath(), path);
		validator1.dispose();
	}

	/**
	 * Tests creation, basic validation
	 */
	@Test
	public void testInMemoryKeystoreValidator() throws Exception
	{
		String path = "src/test/resources/truststores/truststore1.jks";
		KeyStore normalKs = KeyStore.getInstance("JKS");
		normalKs.load(new FileInputStream(path), "the!njs".toCharArray());
		InMemoryKeystoreCertChainValidator validator1 = new InMemoryKeystoreCertChainValidator(
				normalKs, 
				new CRLParameters(), CrlCheckingMode.IGNORE, false);
		X509Certificate[] toValidate = CertificateUtils.loadCertificateChain(
				new FileInputStream("src/test/resources/validator-certs/trusted_client.cert"), 
				Encoding.PEM);
		
		CertificateFactory factory = CertificateFactory.getInstance("X.509");
		CertPath certPath = factory.generateCertPath(Arrays.asList(toValidate));
		
		ValidationResult res = validator1.validate(toValidate);
		assertTrue(res.isValid());
		
		ValidationResult res1 = validator1.validate(certPath);
		assertTrue(res1.isValid());
		
		KeyStore emptyKs = KeyStore.getInstance("JKS");
		emptyKs.load(null);
		validator1.setTruststore(emptyKs);
		ValidationResult res2 = validator1.validate(toValidate);
		assertFalse(res2.isValid());
		assertEquals(validator1.getTruststore(), emptyKs);
		validator1.dispose();
	}

	
	/**
	 * Tests creation, basic validation
	 */
	@Test
	public void testValidationListener() throws Exception
	{
		KeyStore emptyKs = KeyStore.getInstance("JKS");
		emptyKs.load(null);
		InMemoryKeystoreCertChainValidator validator1 = new InMemoryKeystoreCertChainValidator(
				emptyKs, new CRLParameters(), CrlCheckingMode.IGNORE, false);
		X509Certificate[] toValidate = CertificateUtils.loadCertificateChain(
				new FileInputStream("src/test/resources/validator-certs/trusted_client.cert"), 
				Encoding.PEM);
		
		ValidationErrorListener l1 = new ValidationErrorListener()
		{
			public boolean onValidationError(ChainValidationError error)
			{
				vError++;
				System.out.println("L1: " + error);
				return false;
			}
		};
		ValidationErrorListener l2 = new ValidationErrorListener()
		{
			public boolean onValidationError(ChainValidationError error)
			{
				vError++;
				System.out.println("L2: " + error);
				return true;
			}
		};
		validator1.addValidationListener(l1);
		
		vError = 0;
		ValidationResult res = validator1.validate(toValidate);
		assertFalse(res.isValid());
		assertEquals(2, vError);
		
		validator1.addValidationListener(l2);
		vError = 0;
		ValidationResult res1 = validator1.validate(toValidate);
		assertTrue(res1.isValid());
		assertEquals(4, vError);
		
		validator1.removeValidationListener(l1);
		vError = 0;
		ValidationResult res2 = validator1.validate(toValidate);
		assertTrue(res2.isValid());
		assertEquals(2, vError);
		
		validator1.dispose();
	}

	
	/**
	 * Tests update and notifications
	 */
	@Test
	public void testKeystoreValidatorUpdate() throws Exception
	{
		File dir = initDir();
		File ks = new File(dir, "work.jks");
		FileUtils.copyFile(new File("src/test/resources/truststores/empty.jks"), ks);
		
		KeystoreCertChainValidator validator1 = new KeystoreCertChainValidator(
				ks.getPath(), "the!njs".toCharArray(), "JKS", 
				new CRLParameters(), CrlCheckingMode.IGNORE, -1, false);
		X509Certificate[] toValidate = CertificateUtils.loadCertificateChain(
				new FileInputStream("src/test/resources/validator-certs/trusted_client.cert"), 
				Encoding.PEM);
		gotError = false;
		validator1.addUpdateListener(new StoreUpdateListener()
		{
			@Override
			public void loadingNotification(String location, String type,
					Severity level, Exception cause)
			{
				assertEquals(type, StoreUpdateListener.CA_CERT);
				System.out.println(location + " " + cause);
				gotError = true;
			}
		});
		
		ValidationResult res = validator1.validate(toValidate);
		assertFalse(res.isValid());
		
		validator1.setTruststoreUpdateInterval(200);
		FileUtils.copyFile(new File("src/test/resources/truststores/truststore1.jks"), ks);
		Thread.sleep(500);
		
		ValidationResult res2 = validator1.validate(toValidate);
		assertTrue(res2.isValid());

		ks.delete();
		Thread.sleep(500);
		assertTrue(gotError);
		
		validator1.dispose();
	}
	
	/**
	 * Tests update and notifications
	 */
	@Test
	public void testKeystoreValidatorCRL() throws Exception
	{
		String path = "src/test/resources/truststores/truststore1.jks";
		KeystoreCertChainValidator validator1 = new KeystoreCertChainValidator(
				path, "the!njs".toCharArray(), "JKS", 
				new CRLParameters(), CrlCheckingMode.REQUIRE, -1, false);
		X509Certificate[] toValidate1 = CertificateUtils.loadCertificateChain(
				new FileInputStream("src/test/resources/validator-certs/trusted_client.cert"), 
				Encoding.PEM);
		X509Certificate[] toValidate2 = CertificateUtils.loadCertificateChain(
				new FileInputStream("src/test/resources/validator-certs/trusted_client_rev.cert"), 
				Encoding.PEM);
		
		ValidationResult res = validator1.validate(toValidate1);
		assertFalse(res.isValid());
		ValidationResult res2 = validator1.validate(toValidate2);
		assertFalse(res2.isValid());
		
		File dir = initDir();
		validator1.setCrls(Collections.singletonList(dir.getPath() + "/*.crl"));
		
		res = validator1.validate(toValidate1);
		assertFalse(res.isValid());
		res2 = validator1.validate(toValidate2);
		assertFalse(res2.isValid());
		
		validator1.setCRLUpdateInterval(200);
		FileUtils.copyFile(new File("src/test/resources/truststores/maincacrl.pem"), new File(dir, "crl1.crl"));
		Thread.sleep(500);
		
		res = validator1.validate(toValidate1);
		assertTrue(res.isValid());
		res2 = validator1.validate(toValidate2);
		assertFalse(res2.isValid());

		
		
		validator1.dispose();
	}	
}
