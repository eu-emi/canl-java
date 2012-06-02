/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.ocsp;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.URL;
import java.security.cert.X509Certificate;

import junit.framework.Assert;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.ocsp.OCSPReq;
import org.bouncycastle.ocsp.OCSPResp;
import org.bouncycastle.ocsp.SingleResp;
import org.junit.Test;

import eu.emi.security.authn.x509.X509Credential;
import eu.emi.security.authn.x509.helpers.ocsp.OCSPCachingClient;
import eu.emi.security.authn.x509.helpers.ocsp.OCSPClientImpl;
import eu.emi.security.authn.x509.helpers.ocsp.OCSPStatus;
import eu.emi.security.authn.x509.impl.CertificateUtils;
import eu.emi.security.authn.x509.impl.CertificateUtils.Encoding;

public class CacheTest
{
	private static class MockOCSPClient extends OCSPClientImpl
	{
		public int fullQuery = 0;
		public int lowlevelQuery = 0;
		public int verifications = 0;
		
		@Override
		public OCSPStatus queryForCertificate(URL responder, X509Certificate toCheckCert,
				X509Certificate issuerCert, X509Credential requester,
				boolean addNonce, int timeout) throws IOException, OCSPException
		{
			fullQuery++;
			return super.queryForCertificate(responder, toCheckCert, issuerCert, requester, addNonce, timeout);
		}

		@Override
		public OCSPReq createRequest(X509Certificate toCheckCert,
				X509Certificate issuerCert, X509Credential requester,
				boolean addNonce) throws OCSPException
		{
			return super.createRequest(toCheckCert, issuerCert, requester, addNonce);
		}

		@Override
		public OCSPResp send(URL responder, OCSPReq requestO, int timeout)
				throws IOException
		{
			lowlevelQuery++;
			return super.send(responder, requestO, timeout);
		}

		@Override
		public SingleResp verifyResponse(OCSPResp response, X509Certificate toCheckCert,
				X509Certificate issuerCert, byte[] checkNonce) throws OCSPException
		{
			verifications++;
			return super.verifyResponse(response, toCheckCert, issuerCert, checkNonce);
		}
	}
	
	@Test
	public void test() throws Exception
	{
		MockOCSPClient client = new MockOCSPClient();
		URL responder = new URL("https://ocsp.quovadisoffshore.com");
		
		FileInputStream fis = new FileInputStream("src/test/resources/ocsp/switch-qv.pem");
		X509Certificate toCheck = CertificateUtils.loadCertificate(fis,	Encoding.PEM);
		fis.close();
		fis = new FileInputStream("src/test/resources/ocsp/qv-ca.pem");
		X509Certificate issuerCert = CertificateUtils.loadCertificate(fis, Encoding.PEM);
		fis.close();
		
		OCSPStatus status;
		
		OCSPCachingClient notCaching = new OCSPCachingClient(-1, null, null);
		status = notCaching.queryForCertificate(responder, 
				toCheck, issuerCert, null, false, 5000, client);
		Assert.assertEquals(OCSPStatus.good, status);
		Assert.assertEquals(1, client.fullQuery);
		Assert.assertEquals(1, client.lowlevelQuery);
		Assert.assertEquals(1, client.verifications);
		
		status = notCaching.queryForCertificate(responder, 
				toCheck, issuerCert, null, false, 5000, client);
		Assert.assertEquals(OCSPStatus.good, status);
		Assert.assertEquals(2, client.fullQuery);
		Assert.assertEquals(2, client.lowlevelQuery);
		Assert.assertEquals(2, client.verifications);
		
		
		OCSPCachingClient memCaching = new OCSPCachingClient(1000, null, null);
		client = new MockOCSPClient();

		status = memCaching.queryForCertificate(responder, 
				toCheck, issuerCert, null, false, 5000, client);
		Assert.assertEquals(OCSPStatus.good, status);
		Assert.assertEquals(0, client.fullQuery);
		Assert.assertEquals(1, client.lowlevelQuery);
		Assert.assertEquals(1, client.verifications);
		
		status = memCaching.queryForCertificate(responder, 
				toCheck, issuerCert, null, false, 5000, client);
		Assert.assertEquals(OCSPStatus.good, status);
		Assert.assertEquals(0, client.fullQuery);
		Assert.assertEquals(1, client.lowlevelQuery);
		Assert.assertEquals(1, client.verifications);

		Thread.sleep(1100);
		
		status = memCaching.queryForCertificate(responder, 
				toCheck, issuerCert, null, false, 5000, client);
		Assert.assertEquals(OCSPStatus.good, status);
		Assert.assertEquals(0, client.fullQuery);
		Assert.assertEquals(2, client.lowlevelQuery);
		Assert.assertEquals(2, client.verifications);
		
		File dir = new File("target/ocsp_cache");
		FileUtils.deleteDirectory(dir);
		dir.mkdirs();
		OCSPCachingClient diskCaching = new OCSPCachingClient(1000, dir, "ocspcache_");
		client = new MockOCSPClient();
		

		status = diskCaching.queryForCertificate(responder, 
				toCheck, issuerCert, null, false, 5000, client);
		Assert.assertEquals(OCSPStatus.good, status);
		Assert.assertEquals(0, client.fullQuery);
		Assert.assertEquals(1, client.lowlevelQuery);
		Assert.assertEquals(1, client.verifications);
		
		status = diskCaching.queryForCertificate(responder, 
				toCheck, issuerCert, null, false, 5000, client);
		Assert.assertEquals(OCSPStatus.good, status);
		Assert.assertEquals(0, client.fullQuery);
		Assert.assertEquals(1, client.lowlevelQuery);
		Assert.assertEquals(1, client.verifications);
		
		diskCaching.clearMemoryCache();
		
		status = diskCaching.queryForCertificate(responder, 
				toCheck, issuerCert, null, false, 5000, client);
		Assert.assertEquals(OCSPStatus.good, status);
		Assert.assertEquals(0, client.fullQuery);
		Assert.assertEquals(1, client.lowlevelQuery);
		Assert.assertEquals(2, client.verifications);
		
		diskCaching.clearMemoryCache();
		Thread.sleep(1100);
		
		status = diskCaching.queryForCertificate(responder, 
				toCheck, issuerCert, null, false, 5000, client);
		Assert.assertEquals(OCSPStatus.good, status);
		Assert.assertEquals(0, client.fullQuery);
		Assert.assertEquals(2, client.lowlevelQuery);
		Assert.assertEquals(4, client.verifications);
	}
}













