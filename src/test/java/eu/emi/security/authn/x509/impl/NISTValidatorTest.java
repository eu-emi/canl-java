/*
 * Copyright (c) 2011 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.impl;

import java.security.cert.X509Certificate;
import java.util.Set;

import org.junit.Test;

/**
 * @see http://csrc.nist.gov/groups/ST/crypto_apps_infra/pki/pkitesting.html
 * @author K. Benedyczak
 */
public class NISTValidatorTest extends ValidatorTestBase
{
	public static final String GOOD_CA_CERT = "GoodCACert";
	public static final String GOOD_CA_CRL = "GoodCACRL";
	public static final String BAD_SIGNED_CA_CERT = "BadSignedCACert";
	public static final String BAD_SIGNED_CA_CRL = "BadSignedCACRL";
	public static final String DSA_CA_CERT = "DSACACert";
	public static final String DSA_CA_CRL = "DSACACRL";
	public static final String DSA_PARAM_INHERITED_CA_CERT = "DSAParametersInheritedCACert";
	public static final String DSA_PARAM_INHERITED_CA_CRL =  "DSAParametersInheritedCACRL";
	public static final String TRUST_ANCHOR_ROOT_CRL = "TrustAnchorRootCRL";
	public static final String TRUST_ANCHOR_ROOT_CERTIFICATE = "TrustAnchorRootCertificate";


	protected void nistTest(int expectedErrors, String trustedName, 
			String[] chain, String[] crlNames, Set<String> policies) throws Exception
	{
		X509Certificate[] toCheck = new X509Certificate[chain.length];
		for (int i=0; i<chain.length; i++)
			toCheck[i] = loadCert("src/test/resources/NIST/certs/" + chain[i] + ".crt");
		doPathTest(expectedErrors,
				"src/test/resources/NIST/certs/", new String[]{trustedName}, ".crt",
				"src/test/resources/NIST/crls/", crlNames, ".crl",
				toCheck, policies, true, true);
	}

	@Test
	public void test4_1_1() throws Exception
	{
		nistTest(0, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "ValidCertificatePathTest1EE", GOOD_CA_CERT}, 
		                new String[] { GOOD_CA_CRL, TRUST_ANCHOR_ROOT_CRL }, null);
	}

	@Test
	public void test4_1_2() throws Exception
	{
		nistTest(1, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "InvalidCASignatureTest2EE", BAD_SIGNED_CA_CERT}, 
		                new String[] { BAD_SIGNED_CA_CRL, TRUST_ANCHOR_ROOT_CRL }, null);
	}

	@Test
	public void test4_1_3() throws Exception
	{
		nistTest(1, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "InvalidEESignatureTest3EE", GOOD_CA_CERT}, 
		                new String[] { GOOD_CA_CRL, TRUST_ANCHOR_ROOT_CRL }, null);
	}

	@Test
	public void test4_1_4() throws Exception
	{
		nistTest(0, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "ValidDSASignaturesTest4EE", DSA_CA_CERT}, 
		                new String[] { DSA_CA_CRL, TRUST_ANCHOR_ROOT_CRL }, null);
	}
/* FIXME
	@Test
	public void test4_1_5() throws Exception
	{
		nistTest(0, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "ValidDSASignaturesTest4EE", DSA_PARAM_INHERITED_CA_CERT, DSA_CA_CERT}, 
		                new String[] { DSA_PARAM_INHERITED_CA_CRL, DSA_CA_CRL, TRUST_ANCHOR_ROOT_CRL }, null);
	}
*/	
	@Test
	public void test4_1_6() throws Exception
	{
		nistTest(1, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "InvalidDSASignatureTest6EE", DSA_CA_CERT}, 
		                new String[] { DSA_CA_CRL, TRUST_ANCHOR_ROOT_CRL }, null);
	}
}
