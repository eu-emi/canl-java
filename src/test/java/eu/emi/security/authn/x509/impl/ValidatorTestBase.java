/*
 * Copyright (c) 2011 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.impl;

import java.io.File;
import java.io.FileNotFoundException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import static junit.framework.Assert.*;

import org.junit.Assert;

import eu.emi.security.authn.x509.CrlCheckingMode;
import eu.emi.security.authn.x509.ProxySupport;
import eu.emi.security.authn.x509.StoreUpdateListener;
import eu.emi.security.authn.x509.ValidationError;
import eu.emi.security.authn.x509.ValidationResult;
import eu.emi.security.authn.x509.impl.CertificateUtils.Encoding;

public class ValidatorTestBase
{
	protected List<String> resolvePaths(String prefix, String suffix, String[] names) throws FileNotFoundException
	{
		List<String> ret = new ArrayList<String>();
		for (int i=0; i<names.length; i++)
		{
			String name = prefix+names[i]+suffix; 
			if (!name.contains("*") && !name.contains("?"))
			{
				File f = new File(name);
				if (!f.exists())
					throw new FileNotFoundException(name);
			}
			ret.add(name);
		}
		return ret;
	}
	
	protected void doPathTest(
			int expectedErrors,
			String trustAnchorPrefix, String[] trustAnchors, String trustAnchorSuffix,
			String crlPrefix, String[] crls, String crlSuffix, 
			X509Certificate[] toCheck,
			Set<String> policies, ProxySupport proxySupport, CrlCheckingMode revocationSupport) throws Exception
	{
		List<String> trustedLocations = new ArrayList<String>();
		trustedLocations.addAll(resolvePaths(trustAnchorPrefix, trustAnchorSuffix, 
				trustAnchors));
		List<String> crlLocations = new ArrayList<String>();
		crlLocations.addAll(resolvePaths(crlPrefix, crlSuffix, 
				crls));
		CRLParameters crlParameters = new CRLParameters(crlLocations, 
				-1, 
				0, 
				null);
		RevocationParametersExt revocationParams = new RevocationParametersExt(
			revocationSupport, crlParameters);
		
		StoreUpdateListener l = new StoreUpdateListener()
		{
			@Override
			public void loadingNotification(String location, String type,
					Severity level, Exception cause)
			{
				if (level.equals(Severity.ERROR))
				{
					Assert.fail("Error reading a truststore: " + 
							location + " " + type + " " + cause);
				}
			}
		};
		List<StoreUpdateListener> listeners = Collections.singletonList(l);
		
		DirectoryCertChainValidator validator = new DirectoryCertChainValidator(
				trustedLocations,
				Encoding.DER,
				-1, 
				0, 
				null, 
				new ValidatorParamsExt(revocationParams, proxySupport, listeners));
		
		ValidationResult result = validator.validate(toCheck);
		
		List<ValidationError> errors = result.getErrors();
		
		for (ValidationError error: errors)
			System.out.println(error);
		
		if (expectedErrors == Integer.MAX_VALUE)
			assertTrue(expectedErrors > 0);
		else
			assertEquals(expectedErrors, errors.size());
		validator.dispose();
	}	
}
