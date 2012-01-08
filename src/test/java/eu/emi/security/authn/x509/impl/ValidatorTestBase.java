/*
 * Copyright (c) 2011 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.impl;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CRLException;
import java.security.cert.CertStore;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static junit.framework.Assert.*;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.filefilter.WildcardFileFilter;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.extension.X509ExtensionUtil;

import eu.emi.security.authn.x509.ValidationError;
import eu.emi.security.authn.x509.ValidationResult;
import eu.emi.security.authn.x509.helpers.pkipath.BCCertPathValidator;
import eu.emi.security.authn.x509.helpers.pkipath.ExtPKIXParameters;
import eu.emi.security.authn.x509.impl.CertificateUtils.Encoding;

public class ValidatorTestBase
{
	private static Map<String, X509Certificate> certs = new HashMap<String, X509Certificate>();
	private static Map<String, X509CRL> crls = new HashMap<String, X509CRL>();
	
	protected static X509Certificate loadCert(String name) throws IOException
	{
		X509Certificate ret = certs.get(name);
		if (ret != null)
			return ret;
		try
		{
			ret = CertificateUtils.loadCertificate(
					new FileInputStream(name), 
					Encoding.DER);
		} catch (IOException e)
		{
			throw new IOException("Can't load certificate " + name, e);
		}
		certs.put(name, ret);
		return ret;
	}

	protected static X509CRL loadCrl(String name) throws IOException, CertificateException, CRLException
	{
		X509CRL ret = crls.get(name);
		if (ret != null)
			return ret;

		InputStream in = new FileInputStream(name);
		CertificateFactory fact = CertificateFactory.getInstance("X.509");
		ret = (X509CRL)fact.generateCRL(in);
		crls.put(name, ret);
		in.close();
		return ret;
	}
		
	private List<File> resolveNames(String prefix, String suffix, String[] names)
	{
		List<File> ret = new ArrayList<File>();
		for (int i=0; i<names.length; i++)
		{
			File base = new File(prefix + names[i]).getParentFile();
			Collection<File>files = FileUtils.listFiles(base, 
					new WildcardFileFilter(names[i]+suffix), null);
			ret.addAll(files);
		}
		return ret;
	}
	
	private Set<TrustAnchor> readTrustAnchors(String prefix, String suffix, String[] names)
		throws IOException
	{
		Set<TrustAnchor> ret = new HashSet<TrustAnchor>();
		List<File> files = resolveNames(prefix, suffix, names);
		for (File f: files)
			ret.add(getTrustAnchor(f.getPath()));
		return ret;
	}
	
	private List<X509CRL> readCRLs(String prefix, String suffix, String[] names) 
			throws CertificateException, CRLException, IOException
	{
		List<X509CRL> ret = new ArrayList<X509CRL>();
		List<File> files = resolveNames(prefix, suffix, names);
		for (File f: files)
			ret.add(loadCrl(f.getPath()));
		return ret;
	}
	
	private TrustAnchor getTrustAnchor(String trustAnchorName)
			throws IOException
	{
		X509Certificate cert = loadCert(trustAnchorName);
		byte[] extBytes = cert.getExtensionValue(
				X509Extension.nameConstraints.getId());

		if (extBytes != null)
		{
			ASN1Object extValue = X509ExtensionUtil
					.fromExtensionValue(extBytes);

			return new TrustAnchor(cert,
					extValue.getEncoded("DER"));
		}

		return new TrustAnchor(cert, null);
	}	
	

	
	private ValidationResult doPathTestInternal(
			Set<TrustAnchor> trustedSet,
			List<X509CRL> crlsList,
			X509Certificate[] toCheck,
			Set<String> policies, 
			boolean proxySupport, boolean revocationSupport) throws Exception
	{
		CertStore store = CertStore.getInstance("Collection",
				new CollectionCertStoreParameters(crlsList), BouncyCastleProvider.PROVIDER_NAME);
		ExtPKIXParameters params = new ExtPKIXParameters(trustedSet);
		params.addCertStore(store);
		if (revocationSupport)
			params.setCrlMode(CrlCheckingMode.REQUIRE);
		else
			params.setCrlMode(CrlCheckingMode.IGNORE);
		params.setProxySupport(proxySupport);
		
		if (policies != null)
		{
			params.setExplicitPolicyRequired(true);
			params.setInitialPolicies(policies);
		}

		return new BCCertPathValidator().validate(toCheck, params);
	}	

	
	protected void doPathTest(
			int expectedErrors,
			String trustAnchorPrefix, String[] trustAnchors, String trustAnchorSuffix,
			String crlPrefix, String[] crls, String crlSuffix, 
			X509Certificate[] toCheck,
			Set<String> policies, boolean proxySupport, boolean revocationSupport) throws Exception
	{
		Set<TrustAnchor> trustedSet = readTrustAnchors(trustAnchorPrefix, 
				trustAnchorSuffix, trustAnchors);
		List<X509CRL> crlsList = readCRLs(crlPrefix, crlSuffix, crls);

		
		ValidationResult result = doPathTestInternal(trustedSet, crlsList, 
				toCheck, policies, proxySupport, revocationSupport); 
		
		List<ValidationError> errors = result.getErrors();
		
		for (ValidationError error: errors)
			System.out.println(error);
		
		if (expectedErrors == Integer.MAX_VALUE)
			assertTrue(expectedErrors > 0);
		else
			assertEquals(expectedErrors, errors.size());
	}	
}
