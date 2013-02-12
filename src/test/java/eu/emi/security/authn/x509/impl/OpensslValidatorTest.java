/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.impl;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.util.Collections;

import junit.framework.Assert;

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
				NamespaceCheckingMode.EUGRIDPMA_GLOBUS, -1, 
				params);
		
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
		Assert.assertEquals("Other then two errors returned: " + result.toString(), 2, result.getErrors().size());
		Assert.assertTrue("Got wrong message (0): " + result.getErrors().get(0).toString(), 
				result.getErrors().get(0).getMessage().contains("expired"));
		Assert.assertTrue("Got wrong message (1): " + result.getErrors().get(1).toString(), 
				result.getErrors().get(1).getMessage().contains("expired"));
		
		validator1.dispose();
	}
	

	/*
	@Test
	public void testNewHash() throws Exception
	{
		X500Principal subject = new X500Principal("CN=the subca CA,OU=Relaxation,O=Utopia,L=Tropic,C=UG");
		Assert.assertEquals("79356fdd", getOpenSSLCAHash(subject));
	}
	static byte[] subject_name={0x31, 0xB, 0x30, 0x9, 0x6, 0x3, 0x55, 0x4, 0x6, 0xC, 0x2, 0x75, 0x67, 0x31, 0xF, 0x30, 0xD, 0x6, 0x3, 0x55, 0x4, 0x7, 0xC, 0x6, 0x74, 0x72, 0x6F, 0x70, 0x69, 0x63, 0x31, 0xF, 0x30, 0xD, 0x6, 0x3, 0x55, 0x4, 0xA, 0xC, 0x6, 0x75, 0x74, 0x6F, 0x70, 0x69, 0x61, 0x31, 0x13, 0x30, 0x11, 0x6, 0x3, 0x55, 0x4, 0xB, 0xC, 0xA, 0x72, 0x65, 0x6C, 0x61, 0x78, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x31, 0x15, 0x30, 0x13, 0x6, 0x3, 0x55, 0x4, 0x3, 0xC, 0xC, 0x74, 0x68, 0x65, 0x20, 0x73, 0x75, 0x62, 0x63, 0x61, 0x20, 0x63, 0x61
			};
	private static String getOpenSSLCAHash(X500Principal name)
	{
		Digest digest = new SHA1Digest();
		digest.update(subject_name, 0, subject_name.length);
		byte output[] = new byte[digest.getDigestSize()];
		digest.doFinal(output, 0);
		
		return String.format("%02x%02x%02x%02x", output[3] & 0xFF,
				output[2] & 0xFF, output[1] & 0xFF, output[0] & 0xFF);
	}
*/
}