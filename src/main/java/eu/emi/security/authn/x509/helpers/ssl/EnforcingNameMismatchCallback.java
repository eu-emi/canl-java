/*
 * Copyright (c) 2021 Bixbit - Krzysztof Benedyczak. All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.ssl;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import eu.emi.security.authn.x509.impl.CertificateUtils;
import eu.emi.security.authn.x509.impl.FormatMode;
import eu.emi.security.authn.x509.impl.HostnameMismatchCallback2;

public class EnforcingNameMismatchCallback implements HostnameMismatchCallback2
{
	@Override
	public void nameMismatch(X509Certificate peerCertificate, String hostName) throws CertificateException
	{
		throw new CertificateException("Peer's certificate " 
				+ CertificateUtils.format(peerCertificate, FormatMode.COMPACT_ONE_LINE)
				+ " is not matching its hostname " + hostName);
	}
}