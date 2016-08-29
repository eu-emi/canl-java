/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.impl;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.junit.Assert;

import org.junit.Test;

import eu.emi.security.authn.x509.CrlCheckingMode;
import eu.emi.security.authn.x509.OCSPCheckingMode;
import eu.emi.security.authn.x509.OCSPParametes;
import eu.emi.security.authn.x509.ProxySupport;
import eu.emi.security.authn.x509.ValidationResult;
import eu.emi.security.authn.x509.impl.CertificateUtils.Encoding;

public class CRLIfValidTest extends NISTValidatorTestBase
{
	@Test
	public void ifValidFailsOnExpiredCRL() throws KeyStoreException, IOException
	{
		List<String> stores = new ArrayList<String>();
		stores.add("src/test/resources/ca-expired-crl/CA_files/cacert.pem");
		List<String> crlstores = new ArrayList<String>();
		crlstores.add("src/test/resources/ca-expired-crl/cacrl.pem");
		DirectoryCertChainValidator validator = new DirectoryCertChainValidator(
				stores, Encoding.PEM, -1, 0, null,
				new ValidatorParamsExt(new RevocationParametersExt(CrlCheckingMode.IF_VALID, 
						new CRLParameters(crlstores, -1, 0, null), 
						new OCSPParametes(OCSPCheckingMode.IGNORE)), 
						ProxySupport.DENY));
		X509Certificate[] cc = CertificateUtils.loadCertificateChain(new FileInputStream(
				new File("src/test/resources/ca-expired-crl/CA_files/newcerts/8FBFA7974FD13783.pem")), 
				Encoding.PEM);
		ValidationResult result = validator.validate(cc);
		Assert.assertFalse(result.isValid());
	}
	
	
	protected void nistTest(int expectedErrors, String trustedName, 
			String[] chain, String[] crlNames, Set<String> policies) throws Exception
	{
		X509Certificate[] toCheck = new X509Certificate[chain.length];
		for (int i=0; i<chain.length; i++)
			toCheck[i] = loadCert("src/test/resources/NIST/certs/" + chain[i] + ".crt");
		doPathTest(expectedErrors,
				"src/test/resources/NIST/certs/", new String[]{trustedName}, ".crt",
				"src/test/resources/NIST/crls/", crlNames, ".crl",
				toCheck, policies, ProxySupport.ALLOW, CrlCheckingMode.IF_VALID);
	}

	/*
	 * IF_VALID cases (using NIST data):
	 * 1 cert + root:
	 * - Otherwise valid cert + CRL -> should fail
	 * - Otherwise valid cert + invalid CRL -> should fail
	 * 
	 * EE cert + intermediate CA + root:
	 * - no CRL -> should pass
	 * - no CRL only for EE -> should pass
	 * - no CRL only for int CA -> should pass
 	 * - no CRL for EE but CA on its CRL -> should fail
 	 * - no CRL for CA but EE on its CRL -> should fail
	 */
	
	@Test
	public void testSingleOnCrl() throws Exception
	{
		nistTest(1, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "InvalidRevokedEETest3EE", GOOD_CA_CERT}, 
		                new String[] { GOOD_CA_CRL, TRUST_ANCHOR_ROOT_CRL }, null);
	}

	@Test
	public void testSingleInvalidCrl() throws Exception
	{
		nistTest(1, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "InvalidBadCRLSignatureTest4EE", "BadCRLSignatureCACert"}, 
		                new String[] { "BadCRLSignatureCACRL", TRUST_ANCHOR_ROOT_CRL }, null);
	}

	@Test
	public void testMultipleNoEECrl() throws Exception
	{
		nistTest(0, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "InvalidMissingCRLTest1EE", "NoCRLCACert"}, 
		                new String[] { TRUST_ANCHOR_ROOT_CRL }, null);
	}
	
	@Test
	public void testMultipleNoCrl() throws Exception
	{
		nistTest(0, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "InvalidMissingCRLTest1EE", "NoCRLCACert"}, 
		                new String[] { }, null);
	}
	
	@Test
	public void testMultipleNoCACrl() throws Exception
	{
		nistTest(0, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "ValidTwoCRLsTest7EE", "TwoCRLsCACert"}, 
		                new String[] { "TwoCRLsCAGoodCRL" }, null);
	}
	
	@Test
	public void testMultipleNoEECRLAndCARevoked() throws Exception
	{
		nistTest(1, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "InvalidRevokedCATest2EE", "RevokedsubCACert", GOOD_CA_CERT}, 
		                new String[] { GOOD_CA_CRL }, null);
	}

	@Test
	public void testMultipleNoCARLAndEERevoked() throws Exception
	{
		nistTest(1, TRUST_ANCHOR_ROOT_CERTIFICATE, 
	                new String[] { "InvalidRevokedEETest3EE", GOOD_CA_CERT}, 
	                new String[] { GOOD_CA_CRL }, null);
	}

}
