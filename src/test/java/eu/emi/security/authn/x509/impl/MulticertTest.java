/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.impl;

import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.x509.PKIXCertPathReviewer;
import org.bouncycastle.x509.extension.X509ExtensionUtil;

/*
 * Dirty (generally not working) tests for checking PKIX corner cases
 *  - multi certificate CAs in chain etc. 
 */
@SuppressWarnings({"rawtypes", "unchecked", "deprecation"})
public class MulticertTest extends NISTValidatorTestBase
{
	//@Test
	public void test4_4_19() throws Exception
	{
		nistTest(0, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { 
				"ValidSeparateCertificateandCRLKeysTest19EE", 
				"SeparateCertificateandCRLKeysCRLSigningCert", 
				"SeparateCertificateandCRLKeysCertificateSigningCACert"}, 
		                new String[] { "SeparateCertificateandCRLKeysCRL", 
				TRUST_ANCHOR_ROOT_CRL }, null);
	}
	
	// 4.4.19
	//@Test
	public void testValidSeparateCertificateandCRLKeysTest19()
			throws Exception
	{
		String[] certList = new String[] { 
				"SeparateCertificateandCRLKeysCertificateSigningCACert", 
				"SeparateCertificateandCRLKeysCRLSigningCert", 
				"ValidSeparateCertificateandCRLKeysTest19EE" };
		String[] crlList = new String[] { TRUST_ANCHOR_ROOT_CRL, 
				"SeparateCertificateandCRLKeysCRL" };

		PKIXCertPathBuilderResult res = doBuilderTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, null, false, false);

		
		Set  trustedSet = Collections.singleton(getTrustAnchor("src/test/resources/NIST/certs/"+TRUST_ANCHOR_ROOT_CERTIFICATE+".crt"));
		PKIXParameters    params = new PKIXParameters(trustedSet);
		CertStore  store = getStore(certList, crlList);
	        params.addCertStore(store);
	        params.setRevocationEnabled(true);
		PKIXCertPathReviewer reviewer = new PKIXCertPathReviewer(res.getCertPath(), 
				params);
		System.out.println(reviewer.isValidCertPath());
		List[] errors = reviewer.getErrors();
		for (Object e: errors)
			System.out.println(e);
	}
	
	private CertStore getStore(String[] certs,
			String[] crls) throws Exception
	{
		List certsAndCrls = new ArrayList();
		for (int i = 0; i != certs.length; i++)
		{
			certsAndCrls.add(loadCert("src/test/resources/NIST/certs/"+certs[i]+".crt"));
		}

		for (int i = 0; i != crls.length; i++)
		{
			certsAndCrls.add(loadCrl("src/test/resources/NIST/crls/"+crls[i]+".crl"));
		}

		return CertStore.getInstance("Collection", 
				new CollectionCertStoreParameters(certsAndCrls), "BC");
		
	}
	
	private PKIXCertPathBuilderResult doBuilderTest(
			String trustAnchor,
			String[] certs,
			String[] crls,
			Set initialPolicies,
			boolean policyMappingInhibited,
			boolean anyPolicyInhibited)
					throws Exception
	{
		Set  trustedSet = Collections.singleton(getTrustAnchor("src/test/resources/NIST/certs/"+trustAnchor+".crt"));
		X509Certificate endCert = loadCert("src/test/resources/NIST/certs/"+certs[certs.length - 1]+".crt");
		CertStore  store = getStore(certs, crls);

		CertPathBuilder builder = CertPathBuilder.getInstance("PKIX", "BC");

		X509CertSelector endSelector = new X509CertSelector();

		endSelector.setCertificate(endCert);

		PKIXBuilderParameters builderParams = new PKIXBuilderParameters(trustedSet, endSelector);

		if (initialPolicies != null)
		{
			builderParams.setInitialPolicies(initialPolicies);
			builderParams.setExplicitPolicyRequired(true);
		}
		if (policyMappingInhibited)
		{
			builderParams.setPolicyMappingInhibited(policyMappingInhibited);
		}
		if (anyPolicyInhibited)
		{
			builderParams.setAnyPolicyInhibited(anyPolicyInhibited);
		}

		builderParams.addCertStore(store);

		try
		{
			return (PKIXCertPathBuilderResult)builder.build(builderParams);
		}
		catch (CertPathBuilderException e)
		{
			throw (Exception)e.getCause();
		}

	     
	}
	
	private TrustAnchor getTrustAnchor(String trustAnchorName)
			throws Exception
	{
		X509Certificate cert = loadCert(trustAnchorName);
		byte[]          extBytes = cert.getExtensionValue(X509Extensions.NameConstraints.getId());

		if (extBytes != null)
		{
			ASN1Encodable extValue = X509ExtensionUtil.fromExtensionValue(extBytes);

			return new TrustAnchor(cert, extValue.getDEREncoded());
		}

		return new TrustAnchor(cert, null);
	}


}
