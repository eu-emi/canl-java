/*
 * Copyright (c) 2011 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.impl;

import java.security.cert.X509Certificate;
import java.util.Set;

import org.junit.Test;


public class NISTValidatorTest extends ValidatorTestBase
{
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
	public void test1Nist() throws Exception
	{
		nistTest(0, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "ValidCertificatePathTest1EE", GOOD_CA_CERT}, 
		                new String[] { GOOD_CA_CRL, TRUST_ANCHOR_ROOT_CRL }, null);
	}
}
