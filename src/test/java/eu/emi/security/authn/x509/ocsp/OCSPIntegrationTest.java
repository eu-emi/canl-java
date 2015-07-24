/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.ocsp;

import java.io.FileInputStream;
import java.net.URL;
import java.security.cert.X509Certificate;

import org.junit.Test;

import eu.emi.security.authn.x509.CrlCheckingMode;
import eu.emi.security.authn.x509.OCSPCheckingMode;
import eu.emi.security.authn.x509.OCSPParametes;
import eu.emi.security.authn.x509.OCSPResponder;
import eu.emi.security.authn.x509.ProxySupport;
import eu.emi.security.authn.x509.impl.CertificateUtils;
import eu.emi.security.authn.x509.impl.NISTValidatorTestBase;
import eu.emi.security.authn.x509.impl.CertificateUtils.Encoding;


/**
 * Performs a high-level OCSP test. In fact should be little bit extended to test also a case when OCSP responder 
 * returns 'revoked'. Actually we test OCSP URL extraction, successful test, and negative test when a defined OCSP
 * responder returns an error. 
 * 
 * @author K. Benedyczak
 */
public class OCSPIntegrationTest extends NISTValidatorTestBase
{
	@Test
	public void test() throws Exception
	{
		String responder = "http://sr.symcd.com";
		String certToCheck = "src/test/resources/ocsp/mbank.pem";
		String trustedCa = "src/test/resources/ocsp/SymantecClass3EVSSLCA-G3.pem";
		
		X509Certificate toCheck = CertificateUtils.loadCertificate(new FileInputStream(certToCheck), 
				Encoding.PEM);
		X509Certificate responderCert = CertificateUtils.loadCertificate(new FileInputStream(trustedCa), 
				Encoding.PEM);
		
		OCSPParametes ocspParams;

		ocspParams = new OCSPParametes(OCSPCheckingMode.REQUIRE, new OCSPResponder(
				new URL(responder), responderCert));
		
		doPathTest(0, "src/test/resources/ocsp/", new String[] {"SymantecClass3EVSSLCA-G3"}, 
				".pem", "", new String[] {}, "",
				new X509Certificate[] {toCheck}, null, ProxySupport.DENY, 
				CrlCheckingMode.IGNORE, ocspParams);
		
		ocspParams = new OCSPParametes(OCSPCheckingMode.REQUIRE);
		doPathTest(0, "src/test/resources/ocsp/", new String[] {"SymantecClass3EVSSLCA-G3"}, 
				".pem", "", new String[] {}, "",
				new X509Certificate[] {toCheck}, null, ProxySupport.DENY, 
				CrlCheckingMode.IGNORE, ocspParams);

		ocspParams = new OCSPParametes(OCSPCheckingMode.REQUIRE);		
		nistTest(2, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "ValidCertificatePathTest1EE", GOOD_CA_CERT}, 
		                new String[] { GOOD_CA_CRL, TRUST_ANCHOR_ROOT_CRL }, null, ocspParams);

		ocspParams = new OCSPParametes(OCSPCheckingMode.REQUIRE, new OCSPResponder(
				new URL(responder), responderCert));
		nistTest(2, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "ValidCertificatePathTest1EE", GOOD_CA_CERT}, 
		                new String[] { GOOD_CA_CRL, TRUST_ANCHOR_ROOT_CRL }, null, ocspParams);
		
	}
}
