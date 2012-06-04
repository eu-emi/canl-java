/*
 * Copyright (c) 2011 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.impl;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import eu.emi.security.authn.x509.CrlCheckingMode;
import eu.emi.security.authn.x509.OCSPCheckingMode;
import eu.emi.security.authn.x509.OCSPParametes;
import eu.emi.security.authn.x509.ProxySupport;
import eu.emi.security.authn.x509.impl.CertificateUtils.Encoding;

/**
 * Base for NIST tests
 * @see http://csrc.nist.gov/groups/ST/crypto_apps_infra/pki/pkitesting.html
 * @author K. Benedyczak
 */
public abstract class NISTValidatorTestBase extends ValidatorTestBase
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

	private static Map<String, X509Certificate> certs = new HashMap<String, X509Certificate>();

	protected static X509Certificate loadCert(String name) throws IOException
	{
		X509Certificate ret = certs.get(name);
		if (ret != null)
			return ret;
		try
		{
			ret = CertificateUtils.loadCertificate(
					new FileInputStream(name), 
					Encoding.DER);
		} catch (IOException e)
		{
			throw new IOException("Can't load certificate " + name, e);
		}
		certs.put(name, ret);
		return ret;
	}

	protected void nistTest(int expectedErrors, String trustedName, 
			String[] chain, String[] crlNames, Set<String> policies) throws Exception
	{
		nistTest(expectedErrors, trustedName, chain, crlNames, policies, 
				new OCSPParametes(OCSPCheckingMode.IGNORE));
	}

	protected void nistTest(int expectedErrors, String trustedName, 
			String[] chain, String[] crlNames, Set<String> policies, OCSPParametes ocspParams) throws Exception
	{
		X509Certificate[] toCheck = new X509Certificate[chain.length];
		for (int i=0; i<chain.length; i++)
			toCheck[i] = loadCert("src/test/resources/NIST/certs/" + chain[i] + ".crt");
		doPathTest(expectedErrors,
				"src/test/resources/NIST/certs/", new String[]{trustedName}, ".crt",
				"src/test/resources/NIST/crls/", crlNames, ".crl",
				toCheck, policies, ProxySupport.ALLOW, CrlCheckingMode.REQUIRE, ocspParams);
	}
}
