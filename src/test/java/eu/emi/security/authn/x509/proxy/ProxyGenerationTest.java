/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.proxy;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;

import javax.security.auth.x500.X500Principal;

import static org.junit.Assert.*;

import org.bouncycastle.asn1.x509.X509Name;
import org.junit.Test;

import eu.emi.security.authn.x509.X509Credential;
import eu.emi.security.authn.x509.impl.CertificateUtils;
import eu.emi.security.authn.x509.impl.CertificateUtilsTest;
import eu.emi.security.authn.x509.impl.KeystoreCredential;


public class ProxyGenerationTest
{
	/**
	 * Basic generation of the CSR and proxy from CSR.
	 * @throws Exception
	 */
	@Test
	public void testGenerateWithCSR() throws Exception
	{
		X509Credential credential = new KeystoreCredential("src/test/resources/keystore-1.jks",
				CertificateUtilsTest.KS_P, CertificateUtilsTest.KS_P, 
				"mykey", "JKS");
		PrivateKey privateKey = (PrivateKey) credential.getKeyStore().getKey(
				credential.getKeyAlias(), credential.getKeyPassword());
		Certificate c[] = credential.getKeyStore().getCertificateChain(credential.getKeyAlias());
		X509Certificate chain[] = CertificateUtils.convertToX509Chain(c);
		
		ProxyCertificateOptions csrParam = new ProxyCertificateOptions(chain);
		ProxyCSR csr = ProxyCSRGenerator.generate(csrParam);
		
		ProxyRequestOptions proxyParam = new ProxyRequestOptions(chain, csr.getCSR());
		
		X509Certificate[] proxy = ProxyGenerator.generate(proxyParam, privateKey);

		assertEquals(csr.getCSR().getPublicKey(), proxy[0].getPublicKey());
	}
	
	
	@Test
	public void testCSRAttributes() throws Exception
	{
		X509Credential credential = new KeystoreCredential("src/test/resources/keystore-1.jks",
				CertificateUtilsTest.KS_P, CertificateUtilsTest.KS_P, 
				"mykey", "JKS");
		Certificate c[] = credential.getKeyStore().getCertificateChain(credential.getKeyAlias());
		X509Certificate chain[] = CertificateUtils.convertToX509Chain(c);
		ProxyCertificateOptions csrParam = new ProxyCertificateOptions(chain);
		
		csrParam.setPublicKey(chain[0].getPublicKey());
		
		csrParam.setSerialNumber(new BigInteger("1234567"));
		csrParam.setType(ProxyType.RFC3820);
		
		csrParam.setPolicy(new ProxyPolicy(ProxyPolicy.INDEPENDENT_POLICY_OID));
		csrParam.setProxyPathLimit(11);

		csrParam.setProxyTracingIssuer("http://tracing.issuer.example.net");
		csrParam.setProxyTracingSubject("http://tracing.subject.example.net");
		csrParam.setSAMLAssertion("<fake>saml assertion</fake>");
		
		//csrParam.setAttributeCertificates(acs);
		csrParam.setSourceRestrictionExcludedAddresses(new byte[][] {{(byte)192,(byte)168,12,0,
			(byte)255,(byte)255,(byte)255,0}});
		csrParam.setSourceRestrictionPermittedAddresses(new String[] {"192.168.0.0/16"});
		csrParam.setTargetRestrictionExcludedAddresses(new byte[][] {{(byte)192,(byte)168,13,0,
			(byte)255,(byte)255,(byte)255,0}});
		csrParam.setTargetRestrictionPermittedAddresses(new String[] {"192.168.0.0/16", "10.0.0.0/8"});
		
		try
		{
			ProxyCSRGenerator.generate(csrParam);
			fail("Should get IAException");
		} catch (IllegalArgumentException e) 
		{
			//OK
		}
		PrivateKey privateKey = (PrivateKey) credential.getKeyStore().getKey(
				credential.getKeyAlias(), credential.getKeyPassword());
		ProxyCSR csr = ProxyCSRGenerator.generate(csrParam, privateKey);
		
		
		ProxyCSRInfo info = new ProxyCSRInfo(csr.getCSR());
		
		assertEquals(chain[0].getPublicKey(), csr.getCSR().getPublicKey());
		assertEquals(ProxyType.RFC3820, info.getProxyType());
		byte[] subject = csr.getCSR().getCertificationRequestInfo().getSubject().getEncoded();
		X500Principal p = new X500Principal(subject);
		assertTrue(p.getName().contains("CN=1234567"));
		
		assertEquals(new ProxyPolicy(ProxyPolicy.INDEPENDENT_POLICY_OID), info.getPolicy());
		assertEquals(11, (int)info.getProxyPathLimit());
		assertEquals("http://tracing.issuer.example.net", info.getProxyTracingIssuer());
		assertEquals("http://tracing.subject.example.net", info.getProxyTracingSubject());
		assertEquals("<fake>saml assertion</fake>", info.getSAMLExtension());

		assertArrayEquals(new String[][] {{"192.168.0.0/16"}, {"192.168.12.0/24"}}, 
				info.getProxySourceRestrictions());
		assertArrayEquals(new String[][] {{"192.168.0.0/16", "10.0.0.0/8"}, {"192.168.13.0/24"}}, 
				info.getProxyTargetRestrictions());
		
		
	}
	
	/*
	private AttributeCertificate generateAC()
	{
		X509v2AttributeCertificateBuilder builder = new X509v2AttributeCertificateBuilder(
				holder, issuer, 
				new BigInteger("123"), new Date(), new Date());
		ContentSigner
		X509AttributeCertificateHolder acHolder = builder.build(signer);
		return acHolder.toASN1Structure();
	}
	*/
	
	
	/**
	 * Tests whether default key size of the proxy is correct: 1024 bit for 
	 * proxies valid for less then 10 days and 2048 for longer ones.    
	 * @throws Exception
	 */
	@Test
	public void testDefaultKeysize() throws Exception
	{
		X509Credential credential = new KeystoreCredential("src/test/resources/keystore-1.jks",
				CertificateUtilsTest.KS_P, CertificateUtilsTest.KS_P, 
				"mykey", "JKS");
		PrivateKey privateKey = (PrivateKey) credential.getKeyStore().getKey(
				credential.getKeyAlias(), credential.getKeyPassword());
		Certificate c[] = credential.getKeyStore().getCertificateChain(credential.getKeyAlias());
		X509Certificate chain[] = CertificateUtils.convertToX509Chain(c);
		ProxyCertificateOptions param = new ProxyCertificateOptions(chain);
		
		assertEquals(param.getKeyLength(), 1024);
		assertTrue(param.getLifetime() < ProxyCertificateOptions.LONG_PROXY);
		ProxyCertificate proxy1 = ProxyGenerator.generate(param, privateKey);
		int bitLength = ((RSAPublicKey)proxy1.getCertificateChain()[0].getPublicKey()).
				getModulus().bitLength();
		assertEquals(1024, bitLength);
		

		param.setLifetime(3600000);
		ProxyCertificate proxy2 = ProxyGenerator.generate(param, privateKey);
		int bitLength2 = ((RSAPublicKey)proxy2.getCertificateChain()[0].getPublicKey()).
				getModulus().bitLength();
		assertEquals(2048, bitLength2);
	}
}
