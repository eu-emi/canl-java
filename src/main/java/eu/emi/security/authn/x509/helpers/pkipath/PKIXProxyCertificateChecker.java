/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.pkipath;

import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.PKIXCertPathChecker;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import eu.emi.security.authn.x509.helpers.proxy.DraftRFCProxyCertInfoExtension;
import eu.emi.security.authn.x509.helpers.proxy.RFCProxyCertInfoExtension;

/**
 * Checker which handles proxy certificate extensions so BC won't report them as unknown.
 * The real proxy verification is done elsewhere.
 * 
 * @author K. Benedyczak
 */
public class PKIXProxyCertificateChecker extends PKIXCertPathChecker
{
	private static final Set<String> SUPPORTED = new HashSet<String>();
	
	static
	{
		SUPPORTED.add(RFCProxyCertInfoExtension.RFC_EXTENSION_OID);
		SUPPORTED.add(DraftRFCProxyCertInfoExtension.DRAFT_EXTENSION_OID);
	}

	@Override
	public void init(boolean forward) throws CertPathValidatorException
	{
	}

	@Override
	public boolean isForwardCheckingSupported()
	{
		return true;
	}

	@Override
	public Set<String> getSupportedExtensions()
	{
		return SUPPORTED;
	}

	@Override
	public void check(Certificate cert,
			Collection<String> unresolvedCritExts)
			throws CertPathValidatorException
	{
		unresolvedCritExts.remove(RFCProxyCertInfoExtension.RFC_EXTENSION_OID);
		unresolvedCritExts.remove(DraftRFCProxyCertInfoExtension.DRAFT_EXTENSION_OID);
	}
}
