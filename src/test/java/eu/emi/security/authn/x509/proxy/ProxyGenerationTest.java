/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.proxy;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AttributeCertificate;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.AttributeCertificateHolder;
import org.bouncycastle.cert.AttributeCertificateIssuer;
import org.bouncycastle.cert.X509AttributeCertificateHolder;
import org.bouncycastle.cert.X509v2AttributeCertificateBuilder;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.Test;

import eu.emi.security.authn.x509.ValidationResult;
import eu.emi.security.authn.x509.X509CertChainValidator;
import eu.emi.security.authn.x509.X509Credential;
import eu.emi.security.authn.x509.helpers.proxy.ProxyACExtension;
import eu.emi.security.authn.x509.impl.CertificateUtils;
import eu.emi.security.authn.x509.impl.CertificateUtils.Encoding;
import eu.emi.security.authn.x509.impl.CertificateUtilsTest;
import eu.emi.security.authn.x509.impl.DirectoryCertChainValidator;
import eu.emi.security.authn.x509.impl.KeyAndCertCredential;
import eu.emi.security.authn.x509.impl.KeystoreCertChainValidator;
import eu.emi.security.authn.x509.impl.KeystoreCredential;
import eu.emi.security.authn.x509.impl.PEMCredential;
import eu.emi.security.authn.x509.impl.TestSSLHelpers;
import org.junit.Assert;


public class ProxyGenerationTest
{
	/**
	 * Tests whether deserialization from PEM loaded CSR works and whether a proxy generated from CSR has a 
	 * different serial then the previous one. It is also tested if limited flag works on RFC proxies.
	 * @throws Exception
	 */
	@Test
	public void testCSRDeserializationLoading() throws Exception
	{
		X509Credential credential = new KeystoreCredential("src/test/resources/keystore-1.jks",
				CertificateUtilsTest.KS_P, CertificateUtilsTest.KS_P, 
				"mykey", "JKS");
		ProxyCertificateOptions param = new ProxyCertificateOptions(credential.getCertificateChain());
		param.setLimited(true);
		ProxyCertificate proxy1 = ProxyGenerator.generate(param, credential.getKey());
		X509Certificate[] certs = proxy1.getCertificateChain();
		
		ProxyCertificateOptions options = new ProxyCertificateOptions(certs);
		options.setLimited(true);
		ProxyCSR proxyCsr = ProxyCSRGenerator.generate(options);
		PKCS10CertificationRequest req = proxyCsr.getCSR();

		StringWriter stringWriter = new StringWriter();
		JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter);
		pemWriter.writeObject(req);
		pemWriter.close();

		String certRequest = stringWriter.toString();

		PEMParser pemReader = new PEMParser(new StringReader(certRequest));
		PKCS10CertificationRequest req2;
		try {
			req2 = (PKCS10CertificationRequest) pemReader.readObject();
		} finally {
			pemReader.close();
		}
		ProxyCSRInfo info2 = new ProxyCSRInfo(req2);
		assertEquals(new ProxyPolicy(ProxyPolicy.LIMITED_PROXY_OID), info2.getPolicy());
		assertEquals(ProxyType.RFC3820, info2.getProxyType());
		
		ProxyRequestOptions proxy2Param = new ProxyRequestOptions(certs, req2); 
		X509Certificate[] proxy2 = ProxyGenerator.generate(proxy2Param, credential.getKey());
		String[] avas = proxy2[0].getSubjectX500Principal().getName().split(",");
		String[] cn1 = avas[0].split("=");
		String[] cn2 = avas[1].split("=");
		assertNotSame(cn1[1], cn2[1]);
	}
	
	
	/**
	 * Basic generation of the CSR and proxy from CSR.
	 * @FunctionalTest(id="func:proxy-delegate", description="Generates a proxy CSR, then a proxy from this CSR.")
	 * @throws Exception
	 */
	@Test
	public void testGenerateWithCSR() throws Exception
	{
		System.out.println("Running func:proxy-delegate functional test");
		X509Credential credential = new KeystoreCredential("src/test/resources/keystore-1.jks",
				CertificateUtilsTest.KS_P, CertificateUtilsTest.KS_P, 
				"mykey", "JKS");
		PrivateKey privateKey = credential.getKey();
		Certificate c[] = credential.getCertificateChain();
		X509Certificate chain[] = CertificateUtils.convertToX509Chain(c);
		
		ProxyCertificateOptions csrParam = new ProxyCertificateOptions(chain);
		csrParam.setType(ProxyType.LEGACY);
		ProxyCSR csr = ProxyCSRGenerator.generate(csrParam);
		
		ProxyRequestOptions proxyParam = new ProxyRequestOptions(chain, csr.getCSR());
		ProxyCSRInfo csrInfo = new ProxyCSRInfo(csr.getCSR());
		proxyParam.setType(csrInfo.getProxyType());
		X509Certificate[] proxy = ProxyGenerator.generate(proxyParam, privateKey);

		JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
		assertEquals(converter.getPublicKey(csr.getCSR().getSubjectPublicKeyInfo()), proxy[0].getPublicKey());
		assertTrue(proxy[0].getSubjectX500Principal().equals(new X500Principal("CN=proxy, CN=PDPTest Server, O=Testing Organization, L=Testing City, C=EU")));
		assertTrue(new ProxyChainInfo(proxy).getProxyType().equals(ProxyChainType.LEGACY));
		
		X509Certificate eec = ProxyUtils.getEndUserCertificate(proxy);
		assertEquals(chain[0], eec);
		X500Principal eep = ProxyUtils.getOriginalUserDN(proxy);
		assertEquals(chain[0].getSubjectX500Principal(), eep);
		
		assertTrue(proxy[0].getCriticalExtensionOIDs().contains("2.5.29.15"));
	}

	
	/**
	 * Checks if a proxy can be generated with unlimited proxy length
	 */
	@Test
	public void unlimitedProxyIsGenerated() throws Exception
	{
		X509Credential credential = new KeystoreCredential("src/test/resources/keystore-1.jks",
				CertificateUtilsTest.KS_P, CertificateUtilsTest.KS_P, 
				"mykey", "JKS");
		PrivateKey privateKey = credential.getKey();
		Certificate c[] = credential.getCertificateChain();
		X509Certificate chain[] = CertificateUtils.convertToX509Chain(c);
		
		ProxyCertificateOptions csrParam = new ProxyCertificateOptions(chain);
		csrParam.setProxyPathLimit(BaseProxyCertificateOptions.UNLIMITED_PROXY_LENGTH);
		ProxyCSR csr = ProxyCSRGenerator.generate(csrParam);

		assertThat(new ProxyCSRInfo(csr.getCSR()).getProxyPathLimit(), is(Integer.MAX_VALUE));

		ProxyRequestOptions proxyParam = new ProxyRequestOptions(chain, csr.getCSR());
		ProxyCSRInfo csrInfo = new ProxyCSRInfo(csr.getCSR());
		proxyParam.setType(csrInfo.getProxyType());
		proxyParam.setProxyPathLimit(BaseProxyCertificateOptions.UNLIMITED_PROXY_LENGTH);
		X509Certificate[] proxy = ProxyGenerator.generate(proxyParam, privateKey);

		assertThat(new ProxyChainInfo(proxy).getRemainingPathLimit(), is(Integer.MAX_VALUE - 1));
	}

	/**
	 * Checks if a proxy can be generated with limited proxy length
	 */
	@Test
	public void limitedProxyIsGenerated() throws Exception
	{
		X509Credential credential = new KeystoreCredential("src/test/resources/keystore-1.jks",
				CertificateUtilsTest.KS_P, CertificateUtilsTest.KS_P, 
				"mykey", "JKS");
		PrivateKey privateKey = credential.getKey();
		Certificate c[] = credential.getCertificateChain();
		X509Certificate chain[] = CertificateUtils.convertToX509Chain(c);
		
		ProxyCertificateOptions csrParam = new ProxyCertificateOptions(chain);
		csrParam.setProxyPathLimit(3);
		csrParam.setType(ProxyType.RFC3820);
		ProxyCSR csr = ProxyCSRGenerator.generate(csrParam);
		
		assertThat(new ProxyCSRInfo(csr.getCSR()).getProxyPathLimit(), is(3));
		
		ProxyRequestOptions proxyParam = new ProxyRequestOptions(chain, csr.getCSR());
		ProxyCSRInfo csrInfo = new ProxyCSRInfo(csr.getCSR());
		proxyParam.setType(csrInfo.getProxyType());
		proxyParam.setProxyPathLimit(3);
		X509Certificate[] proxy = ProxyGenerator.generate(proxyParam, privateKey);

		assertThat(new ProxyChainInfo(proxy).getRemainingPathLimit(), is(3));
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
		
//		csrParam.setPolicy(new ProxyPolicy(ProxyPolicy.INDEPENDENT_POLICY_OID));
		csrParam.setPolicy(new ProxyPolicy(ProxyPolicy.LIMITED_PROXY_OID));
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
		JcaPEMKeyConverter converter = new JcaPEMKeyConverter();

		assertEquals(chain[0].getPublicKey(), converter.getPublicKey(csr.getCSR().getSubjectPublicKeyInfo()));
		assertEquals(ProxyType.RFC3820, info.getProxyType());
		byte[] subject = csr.getCSR().getSubject().getEncoded();
		X500Principal p = new X500Principal(subject);
		assertTrue(p.getName().contains("CN=1234567"));
		
		//assertEquals(new ProxyPolicy(ProxyPolicy.INDEPENDENT_POLICY_OID), info.getPolicy());
		assertEquals(new ProxyPolicy(ProxyPolicy.LIMITED_PROXY_OID), info.getPolicy());
		assertEquals(11, (int)info.getProxyPathLimit());
		assertEquals("http://tracing.issuer.example.net", info.getProxyTracingIssuer());
		assertEquals("http://tracing.subject.example.net", info.getProxyTracingSubject());
		assertEquals("<fake>saml assertion</fake>", info.getSAMLExtension());

		assertArrayEquals(new String[][] {{"192.168.0.0/16"}, {"192.168.12.0/24"}}, 
				info.getProxySourceRestrictions());
		assertArrayEquals(new String[][] {{"192.168.0.0/16", "10.0.0.0/8"}, {"192.168.13.0/24"}}, 
				info.getProxyTargetRestrictions());
	}
	
	/**
	@FunctionalTest(id="func:proxy-make", description="Generates a proxy from a local cert+priv key," +
			" setting all possible parameters.")
	*/
	@Test
	public void testWithChainInfo() throws Exception
	{
		System.out.println("Running func:proxy-make functional test");

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
		PrivateKey privateKey = credential.getKey();
		X509Certificate chain[] = credential.getCertificateChain();
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
	
	/**
	 * This test tests performs for an EEC cert with each of SHA-2 digests (224, 256, 384, 512),
	 * creates a proxy (should have the same digest alg), 
	 * test an SSL connection with such EEC and finally tests an SSL connection 
	 * with the generated proxy.
	 * @FunctionalTest(id="func:cli-srv-sha2", 
	 *              description="Tests whether connections using " +
	 *		"all sorts of certificates with SHA-2 digests work")
	 * @throws Exception
	 */
	@Test
	public void testSha2Proxy() throws Exception
	{
		System.out.println("Running func:cli-srv-sha2 functional test");

		testSha2Proxy("keystore-sha224.pem", "1.2.840.113549.1.1.14", "SHA224withRSA");
		testSha2Proxy("keystore-sha256.pem", "SHA256withRSA");
		testSha2Proxy("keystore-sha384.pem", "SHA384withRSA");
		testSha2Proxy("keystore-sha512.pem", "SHA512withRSA");
	}	

	private void testSha2Proxy(String fileName, String... algName) throws Exception
	{
		X509Credential credential = new PEMCredential("src/test/resources/test-pems/"+fileName,
				"qwerty".toCharArray());
		PrivateKey privateKey = (PrivateKey) credential.getKeyStore().getKey(
				credential.getKeyAlias(), credential.getKeyPassword());
		Certificate c[] = credential.getKeyStore().getCertificateChain(credential.getKeyAlias());
		X509Certificate chain[] = CertificateUtils.convertToX509Chain(c);
		ProxyCertificateOptions param = new ProxyCertificateOptions(chain);
		
		ProxyCertificate proxy1 = ProxyGenerator.generate(param, privateKey);
		X509Certificate proxy = proxy1.getCertificateChain()[0];
		
		Set<String> validNames = new HashSet<String>();
		Collections.addAll(validNames, algName);
		assertTrue(proxy.getSigAlgName(), validNames.contains(proxy.getSigAlgName()));
		
		X509CertChainValidator v = new DirectoryCertChainValidator(
				Collections.singletonList("src/test/resources/rollover/openssl-trustdir/77ab7b18.0"), 
				Encoding.PEM, -1, 100, null);
		
		TestSSLHelpers sslHelperTest = new TestSSLHelpers();
		sslHelperTest.testClientServer(true, credential, v);
		
		X509Credential proxyCredential = new KeyAndCertCredential(proxy1.getPrivateKey(), 
				proxy1.getCertificateChain());
		sslHelperTest.testClientServer(true, proxyCredential, v);
	}
	
	
	/**
	 * Tests generation of proxy cert with generic extensions set
	 */
	@Test
	public void addACExtTest() throws Exception
	{
		System.out.println("Running func:proxy-make-withCustomExt functional test");

		X509Credential credential = new KeystoreCredential("src/test/resources/keystore-1.jks",
				CertificateUtilsTest.KS_P, CertificateUtilsTest.KS_P, 
				"mykey", "JKS");
		Certificate c[] = credential.getKeyStore().getCertificateChain(credential.getKeyAlias());
		X509Certificate chain[] = CertificateUtils.convertToX509Chain(c);
		ProxyCertificateOptions param = new ProxyCertificateOptions(chain);
		PrivateKey privateKey = (PrivateKey) credential.getKeyStore().getKey(
				credential.getKeyAlias(), credential.getKeyPassword());
		AttributeCertificate ac = generateAC(chain[0].getSubjectX500Principal().getName(), privateKey);
		
		ProxyACExtension extValue = new ProxyACExtension(new AttributeCertificate[] {ac});
		CertificateExtension ce = new CertificateExtension(ProxyACExtension.AC_OID, extValue, false);
		param.addExtension(ce);

		ProxyGenerator.generate(param, privateKey);
	}

	
	/**
	 * Tests generation of proxy cert with different KeyUsage settings
	 */
	@Test
	public void keyUsageTest() throws Exception
	{
		X509Credential credential = new KeystoreCredential("src/test/resources/keystore-1.jks",
				CertificateUtilsTest.KS_P, CertificateUtilsTest.KS_P, 
				"mykey", "JKS");
		Certificate c[] = credential.getKeyStore().getCertificateChain(credential.getKeyAlias());
		X509Certificate chain[] = CertificateUtils.convertToX509Chain(c);
		ProxyCertificateOptions param = new ProxyCertificateOptions(chain);
		PrivateKey privateKey = (PrivateKey) credential.getKeyStore().getKey(
				credential.getKeyAlias(), credential.getKeyPassword());
		
		//the input chain [0] has dsig, nonRep, keyEnc and dataEnc set
		//the input chain [1] has dsig, nonRep, KeyCertSig, CrlSig set
		//the chain[1] is CA cert, so its KU should be ignored.
		// default settings means - copy the effective mask -> should get dsig, nonRep, keyEnc and dataEnc
		ProxyCertificate pc1 = ProxyGenerator.generate(param, privateKey);
		boolean[] ku1 = pc1.getCertificateChain()[0].getKeyUsage();
		assertTrue(ku1[0]);
		assertTrue(ku1[1]);
		assertTrue(ku1[2]);
		assertTrue(ku1[3]);
		assertFalse(ku1[4]);
		assertFalse(ku1[5]);
		assertFalse(ku1[6]);
		assertFalse(ku1[7]);
		
		//now set the KU mask -> should get dsig and keyEnc only
		param.setProxyKeyUsageMask(KeyUsage.keyAgreement | KeyUsage.digitalSignature | KeyUsage.keyEncipherment);
		ProxyCertificate pc2 = ProxyGenerator.generate(param, privateKey);
		boolean[] ku2 = pc2.getCertificateChain()[0].getKeyUsage();
		assertTrue(ku2[0]);
		assertFalse(ku2[1]);
		assertTrue(ku2[2]);
		assertFalse(ku2[3]);
		assertFalse(ku2[4]);
		assertFalse(ku2[5]);
		assertFalse(ku2[6]);
		assertFalse(ku2[7]);
		
		//now test extending the chain with proxy, with default settings. CA cert is ignored, so should get
		// the same KU as above
		ProxyCertificateOptions param2 = new ProxyCertificateOptions(pc2.getCertificateChain());
		ProxyCertificate pc3 = ProxyGenerator.generate(param2, privateKey);
		boolean[] ku3 = pc3.getCertificateChain()[0].getKeyUsage();
		assertTrue(ku3[0]);
		assertFalse(ku3[1]);
		assertTrue(ku3[2]);
		assertFalse(ku3[3]);
		assertFalse(ku3[4]);
		assertFalse(ku3[5]);
		assertFalse(ku3[6]);
		assertFalse(ku3[7]);
		
	}
	
	/**
	 * Tests generation of proxy cert with long lifetime and stretching of the limits
	 */
	@Test
	public void testLifetime() throws Exception
	{
		System.out.println("Running regression:proxy-time-overflow test");

		X509Credential credential = new KeystoreCredential("src/test/resources/keystore-1.jks",
				CertificateUtilsTest.KS_P, CertificateUtilsTest.KS_P, 
				"mykey", "JKS");
		Certificate c[] = credential.getKeyStore().getCertificateChain(credential.getKeyAlias());
		X509Certificate chain[] = CertificateUtils.convertToX509Chain(c);
		ProxyCertificateOptions param = new ProxyCertificateOptions(chain);
		param.setLifetime(Integer.MAX_VALUE, TimeUnit.SECONDS);
		PrivateKey privateKey = (PrivateKey) credential.getKeyStore().getKey(
				credential.getKeyAlias(), credential.getKeyPassword());

		//be careful - certificate dates have 1s precision. So add/remove 1001 ms.
		Date end = new Date(((long)Integer.MAX_VALUE)*1000L+System.currentTimeMillis()-1001);
		
		ProxyCertificate pc = ProxyGenerator.generate(param, privateKey);
		Date notAfter = pc.getCertificateChain()[0].getNotAfter();
		
		Date endPlus = new Date(((long)Integer.MAX_VALUE)*1000L+System.currentTimeMillis()+1001);

		System.out.println("Got: " + notAfter.getTime());
		System.out.println("Should be earlier: " + end.getTime());
		System.out.println("Should be later: " + endPlus.getTime());
		assertTrue(notAfter.after(end));
		assertTrue(notAfter.before(endPlus));
		
		KeystoreCertChainValidator validator = new KeystoreCertChainValidator("src/test/resources/truststore-1.jks",
				CertificateUtilsTest.KS_P, "JKS", -1);
		ValidationResult res = validator.validate(pc.getCertificateChain());
		System.out.println(res);
		Assert.assertTrue(res.isValid());
		
		
		param.setLifetime(0, TimeUnit.SECONDS);
		pc = ProxyGenerator.generate(param, privateKey);
		Thread.sleep(1500);
		res = validator.validate(pc.getCertificateChain());
		System.out.println(res);
		Assert.assertTrue(res.isValid());
		
		Date vstart = new Date();
		vstart.setTime(12345000L);
		Date vend = new Date();
		vend.setTime(12346000L);
		
		param.setValidityBounds(vstart, vend);
		pc = ProxyGenerator.generate(param, privateKey);
		Assert.assertEquals(vstart, pc.getCertificateChain()[0].getNotBefore());
		Assert.assertEquals(vend, pc.getCertificateChain()[0].getNotAfter());
		
		
		res = validator.validate(pc.getCertificateChain());
		System.out.println(res);
		Assert.assertFalse(res.isValid());
	}
	
	/**
	 * Creates a legacy proxy. Then uses the chain with a proxy to create another one.
	 * Verifies is the 2nd proxy has its type correctly set.
	 * <p>
	 * The 2nd proxy is created using two methods: with CSR and without to simulate local 
	 * generation of subsequent proxy (for whatever reasons)
	 * @throws Exception
	 */
	@Test
	public void testProxyChainGeneration() throws Exception
	{
		X509Credential credential = new KeystoreCredential("src/test/resources/keystore-1.jks",
				CertificateUtilsTest.KS_P, CertificateUtilsTest.KS_P, 
				"mykey", "JKS");
		Certificate c[] = credential.getKeyStore().getCertificateChain(credential.getKeyAlias());
		X509Certificate chain[] = CertificateUtils.convertToX509Chain(c);
		ProxyCertificateOptions pc1Param = new ProxyCertificateOptions(chain);
		
		pc1Param.setType(ProxyType.LEGACY);
		pc1Param.setLimited(true);

		ProxyCertificate pc1 = ProxyGenerator.generate(pc1Param, credential.getKey());
		
		ProxyChainInfo pc1i = new ProxyChainInfo(pc1.getCertificateChain());
		assertEquals(ProxyChainType.LEGACY, pc1i.getProxyType());
		assertEquals(true, pc1i.isLimited());
		
		ProxyCertificateOptions pc2Param = new ProxyCertificateOptions(pc1.getCertificateChain());
		ProxyCSR certReq = ProxyCSRGenerator.generate(pc2Param);
		ProxyRequestOptions pc2ReqParam = new ProxyRequestOptions(pc1.getCertificateChain(), certReq.getCSR());
		X509Certificate[] pc2 = ProxyGenerator.generate(pc2ReqParam, credential.getKey());
		ProxyChainInfo pc2i = new ProxyChainInfo(pc2);
		assertEquals(ProxyChainType.LEGACY, pc2i.getProxyType());
		assertEquals(true, pc2i.isLimited());
		
		ProxyCertificateOptions pc2LocalParam = new ProxyCertificateOptions(pc1.getCertificateChain());
		ProxyCertificate pc2Local = ProxyGenerator.generate(pc2LocalParam, credential.getKey());
		ProxyChainInfo pc2Locali = new ProxyChainInfo(pc2Local.getCertificateChain());
		assertEquals(ProxyChainType.LEGACY, pc2Locali.getProxyType());
		assertEquals(true, pc2Locali.isLimited());
		
		assertTrue(pc2Local.getCertificateChain()[0].getCriticalExtensionOIDs().contains("2.5.29.15"));
	}

}



