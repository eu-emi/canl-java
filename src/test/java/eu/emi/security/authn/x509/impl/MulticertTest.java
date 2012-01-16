/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.impl;

import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathValidator;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.PKIXCertPathValidatorResult;
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
import org.junit.Test;

/*
 * Dirty (generally not working) tests for checking PKIX corner cases
 *  - multi certificate CAs in chain etc. 
 */
@SuppressWarnings({"rawtypes", "unchecked", "deprecation"})
public class MulticertTest extends NISTValidatorTestBase
{
	
	//@Test
	public void test4_13_19() throws Exception
	{
		convertToNist(0,
				new String[] { "nameConstraintsDN1CACert",
						"nameConstraintsDN1CACRL" },
				new String[] { "nameConstraintsDN1SelfIssuedCACert" },
				new String[] { "ValidDNnameConstraintsTest19EE" });
	}

	private void convertToNist(int e, String[] a, String[] b, String[] c)
			throws Exception
	{
		List<String> crls = new ArrayList<String>();
		for (int i=1; i<b.length; i++)
			crls.add(b[i]);
		for (int i=1; i<a.length; i++)
			crls.add(a[i]);
		crls.add(TRUST_ANCHOR_ROOT_CRL);
		nistTest(e, TRUST_ANCHOR_ROOT_CERTIFICATE, new String[] { c[0],
				b[0], a[0] }, crls.toArray(new String[0]), null);
	}

}
