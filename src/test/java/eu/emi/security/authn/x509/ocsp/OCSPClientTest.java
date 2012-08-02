/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.ocsp;

import java.io.FileInputStream;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.Date;

import junit.framework.Assert;

import org.junit.Test;

import eu.emi.security.authn.x509.X509Credential;
import eu.emi.security.authn.x509.helpers.ocsp.OCSPClientImpl;
import eu.emi.security.authn.x509.helpers.ocsp.OCSPResult;
import eu.emi.security.authn.x509.impl.CertificateUtils;
import eu.emi.security.authn.x509.impl.CertificateUtils.Encoding;

public class OCSPClientTest
{
	private static class Case
	{
		String responder;
		String toCheck;
		String issuer;

		public Case(String issuer,String toCheck, String responder)
		{
			this.responder = responder;
			this.toCheck = toCheck;
			this.issuer = issuer;
		}
	}
	
	private static Case[] cases = {
		new Case("src/test/resources/ocsp/qv-ca.pem", "src/test/resources/ocsp/switch-qv.pem", 
				"https://ocsp.quovadisoffshore.com"),
//		new Case("src/test/resources/ocsp/VeriSignSSLCA.pem", "src/test/resources/ocsp/mbank.pem", 
//				"http://EVSecure-ocsp.verisign.com"),
//		new Case("src/test/resources/ocsp/usertrust-ca.pem", "src/test/resources/ocsp/terena-ssl.pem", 
//				"http://ocsp.usertrust.com"),
//		new Case("src/test/resources/ocsp/digicert-ca.pem", "src/test/resources/ocsp/digicert.pem", 
//				"http://ocsp.digicert.com"),
		//new Case("src/test/resources/ocsp/algierian-ca.pem", "src/test/resources/ocsp/algierian-nagios.pem", 
		//		"https://ca.grid.arn.dz:2560"),
		//new Case("src/test/resources/ocsp/CESNET-CA-Root.pem", "src/test/resources/ocsp/CESNET.pem", 
		//		"http://ocsp.cesnet-ca.cz/"),
	};

	@Test
	public void test() throws Exception
	{
		OCSPClientImpl client = new OCSPClientImpl();
		
		
		for (Case testCase: cases)
		{
			System.out.println("--- TEST CASE for: " + testCase.responder + " ---");
			FileInputStream fis = new FileInputStream(testCase.toCheck);
			X509Certificate toCheck = CertificateUtils.loadCertificate(fis,	Encoding.PEM);
			fis.close();
			fis = new FileInputStream(testCase.issuer);
			X509Certificate issuerCert = CertificateUtils.loadCertificate(fis, Encoding.PEM);
			fis.close();

			// BufferedReader br = new BufferedReader(new
			// InputStreamReader(System.in));
			// char [] pass = br.readLine().trim().toCharArray();
			// X509Credential credential = new
			// KeystoreCredential("/home/golbi/PL-Grid/CERTS/PL-Grid-CA/KrzysztofBenedyczak-3/KrzysztofBenedyczak-keystore.jks",
			// pass, pass, "krzysztofbenedyczak", "JKS");
			X509Credential credential = null;

			URL responder = new URL(testCase.responder);

			OCSPResult status = client.queryForCertificate(responder,
					toCheck, issuerCert, credential, false, 5000);
			System.out.println("Got status: " + status);
			System.out.println("--- TEST CASE END ---");
			
		}
	}
	
	@Test
	public void testCachePragma()
	{
		Assert.assertNull(OCSPClientImpl.getNextUpdateFromCacheHeader(null));
		Date d = OCSPClientImpl.getNextUpdateFromCacheHeader("cache-control: max-age=86,public,no-transform,must-revalidate");
		long now = System.currentTimeMillis();
		Assert.assertTrue(now+85000 < d.getTime());
		Assert.assertTrue(now+87000 > d.getTime());
		
		d = OCSPClientImpl.getNextUpdateFromCacheHeader("cache-control: max-age=86");
		now = System.currentTimeMillis();
		Assert.assertTrue(now+85000 < d.getTime());
		Assert.assertTrue(now+87000 > d.getTime());
	}
}
