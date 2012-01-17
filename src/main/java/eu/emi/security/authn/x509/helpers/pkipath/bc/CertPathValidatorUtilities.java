/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.pkipath.bc;

import java.security.cert.CertificateParsingException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Set;

import org.bouncycastle.jce.provider.AnnotatedException;
import org.bouncycastle.x509.ExtendedPKIXBuilderParameters;
import org.bouncycastle.x509.ExtendedPKIXParameters;

public class CertPathValidatorUtilities extends
		org.bouncycastle.jce.provider.CertPathValidatorUtilities
{
	/**
	 * {@inheritDoc}
	 */
	protected static TrustAnchor findTrustAnchor(X509Certificate cert,
			Set<?> trustAnchors, String sigProvider)
			throws AnnotatedException
	{
		return org.bouncycastle.jce.provider.CertPathValidatorUtilities
				.findTrustAnchor(cert, trustAnchors,
						sigProvider);
	}

	/**
	 * {@inheritDoc}
	 */
	protected static void addAdditionalStoresFromAltNames(
			X509Certificate cert, ExtendedPKIXParameters pkixParams)
			throws CertificateParsingException
	{
		org.bouncycastle.jce.provider.CertPathValidatorUtilities
				.addAdditionalStoresFromAltNames(cert,
						pkixParams);
	}

	/**
	 * {@inheritDoc}
	 */
	protected static Collection<?> findIssuerCerts(X509Certificate cert,
			ExtendedPKIXBuilderParameters pkixParams)
			throws AnnotatedException
	{
		return org.bouncycastle.jce.provider.CertPathValidatorUtilities
				.findIssuerCerts(cert, pkixParams);
	}
}
