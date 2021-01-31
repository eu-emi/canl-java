/*
 * Copyright (c) 2021 Bixbit - Krzysztof Benedyczak. All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.ssl;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import eu.emi.security.authn.x509.impl.HostnameMismatchCallback2;

public class DisabledNameMismatchCallback implements HostnameMismatchCallback2
{
	@Override
	public void nameMismatch(X509Certificate peerCertificate, String hostName) throws CertificateException
	{
	}
}