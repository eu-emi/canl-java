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
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import static org.junit.Assert.*;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AttributeCertificate;
import org.bouncycastle.cert.AttributeCertificateHolder;
import org.bouncycastle.cert.AttributeCertificateIssuer;
import org.bouncycastle.cert.X509AttributeCertificateHolder;
import org.bouncycastle.cert.X509v2AttributeCertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
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
		csrParam.setType(ProxyType.LEGACY);
		ProxyCSR csr = ProxyCSRGenerator.generate(csrParam);
		
		ProxyRequestOptions proxyParam = new ProxyRequestOptions(chain, csr.getCSR());
		ProxyCSRInfo csrInfo = new ProxyCSRInfo(csr.getCSR());
		proxyParam.setType(csrInfo.getProxyType());
		X509Certificate[] proxy = ProxyGenerator.generate(proxyParam, privateKey);

		assertEquals(csr.getCSR().getPublicKey(), proxy[0].getPublicKey());
		assertTrue(proxy[0].getSubjectX500Principal().equals(new X500Principal("CN=proxy, CN=PDPTest Server, O=Testing Organization, L=Testing City, C=EU")));
		assertTrue(new ProxyChainInfo(proxy).getProxyType().equals(ProxyChainType.LEGACY));
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
		PrivateKey privateKey = (PrivateKey) credential.getKeyStore().getKey(
				credential.getKeyAlias(), credential.getKeyPassword());
		
		csrParam.setPublicKey(chain[0].getPublicKey());
		
		csrParam.setSerialNumber(new BigInteger("1234567"));
		csrParam.setType(ProxyType.RFC3820);
		
		csrParam.setPolicy(new ProxyPolicy(ProxyPolicy.INDEPENDENT_POLICY_OID));
		csrParam.setProxyPathLimit(11);

		csrParam.setProxyTracingIssuer("http://tracing.issuer.example.net");
		csrParam.setProxyTracingSubject("http://tracing.subject.example.net");
		csrParam.setSAMLAssertion("<fake>saml assertion</fake>");
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
	
	@Test
	public void testWithChainInfo() throws Exception
	{
		X509Credential credential = new KeystoreCredential("src/test/resources/keystore-1.jks",
				CertificateUtilsTest.KS_P, CertificateUtilsTest.KS_P, 
				"mykey", "JKS");
		Certificate c[] = credential.getKeyStore().getCertificateChain(credential.getKeyAlias());
		X509Certificate chain[] = CertificateUtils.convertToX509Chain(c);
		ProxyCertificateOptions param = new ProxyCertificateOptions(chain);
		PrivateKey privateKey = (PrivateKey) credential.getKeyStore().getKey(
				credential.getKeyAlias(), credential.getKeyPassword());
		//yep - in reality privKey will be different but here we don't care.
		AttributeCertificate ac = generateAC(chain[0].getSubjectX500Principal().getName(),
				privateKey);
		byte[] origIssuer = ac.getAcinfo().getIssuer().getEncoded();
		param.setAttributeCertificates(new AttributeCertificate[] {ac});
		
		param.setSerialNumber(new BigInteger("1234567"));
		param.setType(ProxyType.DRAFT_RFC);
		
		param.setPolicy(new ProxyPolicy(ProxyPolicy.LIMITED_PROXY_OID));
		param.setProxyPathLimit(11);

		param.setProxyTracingIssuer("http://tracing.issuer.example.net");
		param.setProxyTracingSubject("http://tracing.subject.example.net");
		param.setSAMLAssertion("<fake>saml assertion</fake>");
		param.setSourceRestrictionPermittedAddresses(new byte[][] {{(byte)192,(byte)168,12,0,
			(byte)255,(byte)255,(byte)255,0}});
		param.setSourceRestrictionExcludedAddresses(new String[] {"192.168.13.0/24"});
		param.setTargetRestrictionPermittedAddresses(new byte[][] {{(byte)192,(byte)168,0,0,
			(byte)255,(byte)255,0,0}});
		param.setTargetRestrictionExcludedAddresses(new String[] {"192.168.3.0/24", "192.168.14.0/24"});
		
		
		ProxyCertificate proxy1 = ProxyGenerator.generate(param, privateKey);
		ProxyChainInfo chainInfo = new ProxyChainInfo(proxy1.getCertificateChain());
		
		assertNotNull(chainInfo.getAttributeCertificateExtensions()[0]);
		assertEquals(1, chainInfo.getAttributeCertificateExtensions()[0].length);
		byte[] issuerRaw = chainInfo.getAttributeCertificateExtensions()[0][0].getAcinfo().
				getIssuer().getEncoded();
		assertArrayEquals(origIssuer, issuerRaw);
		
		assertEquals(0, chainInfo.getFirstProxyPosition());
		assertEquals(new ProxyPolicy(ProxyPolicy.LIMITED_PROXY_OID), 
				chainInfo.getPolicy()[0]);
		assertEquals(11, chainInfo.getRemainingPathLimit());
		assertEquals(ProxyChainType.DRAFT_RFC, chainInfo.getProxyType());
		assertTrue(chainInfo.isLimited());
		assertEquals(new BigInteger("1234567"), chainInfo.getSerialNumbers()[0]);

		assertEquals("http://tracing.issuer.example.net", chainInfo.getProxyTracingIssuers()[0]);
		assertEquals("http://tracing.subject.example.net", chainInfo.getProxyTracingSubjects()[0]);
		assertEquals("<fake>saml assertion</fake>", chainInfo.getSAMLExtensions()[0]);
		
		assertArrayEquals(new byte[][][] {{{(byte)192,(byte)168,12,0, (byte)255,(byte)255,(byte)255,0}}, 
			{{(byte)192,(byte)168,13,(byte)0, (byte)255,(byte)255,(byte)255,(byte)0}}}, 
				chainInfo.getProxySourceRestrictions());
		assertArrayEquals(new byte[][][] {{{(byte)192,(byte)168,0,0,(byte)255,(byte)255,0,0}}, 
				{{(byte)192,(byte)168,3,0, (byte)255,(byte)255,(byte)255,0}, 
				{(byte)192,(byte)168,14,0, (byte)255,(byte)255,(byte)255,0}}}, 
				chainInfo.getProxyTargetRestrictions());
		
		assertTrue(chainInfo.isHostAllowedAsSource(new byte[] {(byte)192,(byte)168,12,20}));
		assertFalse(chainInfo.isHostAllowedAsSource(new byte[] {(byte)192,(byte)168,13,(byte)129}));
		assertTrue(chainInfo.isHostAllowedAsTarget(new byte[] {(byte)192,(byte)168,1,1}));
		assertFalse(chainInfo.isHostAllowedAsTarget(new byte[] {(byte)192,(byte)168,14,1}));
		assertFalse(chainInfo.isHostAllowedAsTarget(new byte[] {(byte)192,(byte)168,3,13}));
	}
	
	private AttributeCertificate generateAC(String subject, PrivateKey privateKey) 
			throws OperatorCreationException
	{
		AttributeCertificateIssuer issuer = new AttributeCertificateIssuer(
				new X500Name("CN=fake VOMS,C=IT"));
		AttributeCertificateHolder holder = new AttributeCertificateHolder(
				new X500Name(subject));
		X509v2AttributeCertificateBuilder builder = new X509v2AttributeCertificateBuilder(
				holder, issuer, 
				new BigInteger("123"), new Date(), new Date());
		
		ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(privateKey);
		X509AttributeCertificateHolder acHolder = builder.build(signer);
		return acHolder.toASN1Structure();
	}
	
	
	
	@Test
	public void testCSRForLegacy() throws Exception
	{
		X509Credential credential = new KeystoreCredential("src/test/resources/keystore-1.jks",
				CertificateUtilsTest.KS_P, CertificateUtilsTest.KS_P, 
				"mykey", "JKS");
		Certificate c[] = credential.getKeyStore().getCertificateChain(credential.getKeyAlias());
		X509Certificate chain[] = CertificateUtils.convertToX509Chain(c);
		ProxyCertificateOptions csrParam = new ProxyCertificateOptions(chain);
		
		csrParam.setType(ProxyType.LEGACY);
		csrParam.setLimited(true);

		ProxyCSR csr = ProxyCSRGenerator.generate(csrParam);
		
		ProxyCSRInfo info = new ProxyCSRInfo(csr.getCSR());
		
		assertEquals(ProxyType.LEGACY, info.getProxyType());
		assertEquals(true, info.isLimited());
	}
	
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
