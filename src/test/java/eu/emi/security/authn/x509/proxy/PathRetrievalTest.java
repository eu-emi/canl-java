/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.proxy;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.List;

import org.junit.Assert;
import org.junit.Test;

import eu.emi.security.authn.x509.NamespaceCheckingMode;
import eu.emi.security.authn.x509.ValidationErrorCode;
import eu.emi.security.authn.x509.ValidationResult;
import eu.emi.security.authn.x509.impl.CertificateUtils;
import eu.emi.security.authn.x509.impl.OpensslCertChainValidator;
import eu.emi.security.authn.x509.impl.PEMCredential;

/**
 * @author K. Benedyczak
 */
public class PathRetrievalTest
{
	@Test
	public void testReturningOfFullValidatedPath() throws Exception
	{
		OpensslCertChainValidator validator = new OpensslCertChainValidator(
				"src/test/resources/glite-utiljava/grid-security/certificates");
		KeyStore ks = CertificateUtils.loadPEMKeystore(new FileInputStream(
				"src/test/resources/glite-utiljava/trusted-certs/trusted_client.proxy_rfc_plen.proxy_rfc.grid_proxy"), 
				null, "test".toCharArray());
		X509Certificate[] toCheck = CertificateUtils.convertToX509Chain(
				ks.getCertificateChain(CertificateUtils.DEFAULT_KEYSTORE_ALIAS));
		
		ValidationResult res = validator.validate(toCheck);
		Assert.assertNotNull(res.getValidChain());
		
		List<X509Certificate> ret = res.getValidChain();
		Assert.assertEquals(1+toCheck.length, ret.size());
		for (int i=0; i<ret.size()-1; i++)
		{
			Assert.assertTrue(ret.get(i).getIssuerX500Principal().equals(
					ret.get(i+1).getSubjectX500Principal()));
		}
	}

	@Test
	public void validationOfMixedChain() throws Exception
	{
		PEMCredential credential = new PEMCredential("src/test/resources/glite-utiljava/trusted-certs/trusted_client.proxy_rfc_plen.grid_proxy",
				"test".toCharArray());
		ProxyCertificateOptions opts = new ProxyCertificateOptions(credential.getCertificateChain());
		opts.setType(ProxyType.LEGACY);
		ProxyCertificate pc = ProxyGenerator.generate(opts, credential.getKey());
		OpensslCertChainValidator validator = new OpensslCertChainValidator(
				"src/test/resources/glite-utiljava/grid-security/certificates",
				NamespaceCheckingMode.IGNORE, -1);
		ValidationResult valRes = validator.validate(pc.getCertificateChain());
		Assert.assertEquals(1, valRes.getErrors().size());
		Assert.assertEquals(ValidationErrorCode.proxyTypeInconsistent, valRes.getErrors().get(0).getErrorCode());
	}
	
	
	@Test
	public void validationOfWronglyLimitedChain() throws Exception
	{
		PEMCredential credential = new PEMCredential("src/test/resources/glite-utiljava/trusted-certs/trusted_client.proxy_rfc_lim.grid_proxy",
				"test".toCharArray());
		ProxyCertificateOptions opts = new ProxyCertificateOptions(credential.getCertificateChain());
		opts.setLimited(false);
		ProxyCertificate pc = ProxyGenerator.generate(opts, credential.getKey());
		OpensslCertChainValidator validator = new OpensslCertChainValidator(
				"src/test/resources/glite-utiljava/grid-security/certificates",
				NamespaceCheckingMode.IGNORE, -1);
		ValidationResult valRes = validator.validate(pc.getCertificateChain());
		
		System.out.println(valRes);
		Assert.assertEquals(1, valRes.getErrors().size());
		Assert.assertEquals(ValidationErrorCode.proxyInconsistentlyLimited, valRes.getErrors().get(0).getErrorCode());
	}
}
