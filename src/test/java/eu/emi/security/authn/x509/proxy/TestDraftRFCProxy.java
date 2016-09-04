/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.proxy;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import java.io.FileInputStream;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import org.junit.Test;

import eu.emi.security.authn.x509.X509Credential;
import eu.emi.security.authn.x509.helpers.proxy.ExtendedProxyType;
import eu.emi.security.authn.x509.helpers.proxy.ProxyHelper;
import eu.emi.security.authn.x509.impl.CertificateUtils;
import eu.emi.security.authn.x509.impl.CertificateUtilsTest;
import eu.emi.security.authn.x509.impl.KeystoreCredential;
import eu.emi.security.authn.x509.impl.CertificateUtils.Encoding;

public class TestDraftRFCProxy
{
	@Test
	public void shouldLoadOriginalGT3ProxyWithPathLimit() throws Exception
	{
		X509Certificate[] proxyChain = CertificateUtils.loadCertificateChain(
				new FileInputStream("src/test/resources/GT3_proxy/GT3_proxy"), 
				Encoding.PEM);
		
		ExtendedProxyType proxyType = ProxyHelper.getProxyType(proxyChain[0]);
		
		assertThat(proxyType, is(ExtendedProxyType.DRAFT_RFC));
		assertThat(ProxyHelper.getProxyPathLimit(proxyChain[0]), is(42));
	}

	
	@Test
	public void generatedGT3ProxyWithPathLimitIsParsed() throws Exception
	{
		X509Credential credential = new KeystoreCredential("src/test/resources/keystore-1.jks",
				CertificateUtilsTest.KS_P, CertificateUtilsTest.KS_P, 
				"mykey", "JKS");
		PrivateKey privateKey = credential.getKey();
		Certificate c[] = credential.getCertificateChain();
		X509Certificate chain[] = CertificateUtils.convertToX509Chain(c);
		
		ProxyCertificateOptions csrParam = new ProxyCertificateOptions(chain);
		csrParam.setProxyPathLimit(3);
		csrParam.setType(ProxyType.DRAFT_RFC);
		ProxyCSR csr = ProxyCSRGenerator.generate(csrParam);
		
		assertThat(new ProxyCSRInfo(csr.getCSR()).getProxyPathLimit(), is(3));
		
		ProxyRequestOptions proxyParam = new ProxyRequestOptions(chain, csr.getCSR());
		ProxyCSRInfo csrInfo = new ProxyCSRInfo(csr.getCSR());
		proxyParam.setType(csrInfo.getProxyType());
		proxyParam.setProxyPathLimit(3);
		X509Certificate[] proxy = ProxyGenerator.generate(proxyParam, privateKey);

		ExtendedProxyType proxyType = ProxyHelper.getProxyType(proxy[0]);
		assertThat(proxyType, is(ExtendedProxyType.DRAFT_RFC));
		assertThat(ProxyHelper.getProxyPathLimit(proxy[0]), is(3));
	}
}



