/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.revocation;

import java.security.cert.X509Certificate;

import eu.emi.security.authn.x509.helpers.pkipath.SimpleValidationErrorException;

/**
 * Used to check revocation using a single revocation checking mechanism.
 * @author K. Benedyczak
 */
public interface RevocationChecker
{
	/**
	 * Checks revocation.
	 * @param certitifcate certificate
	 * @param issuer issuer
	 * @return whether the revocation was successfully checked or if the status is unknown.
	 * @throws SimpleValidationErrorException if revocation validation finished with error, in particular
	 * also when certificate is revoked.
	 */
	public RevocationStatus checkRevocation(X509Certificate certitifcate,
			X509Certificate issuer) throws SimpleValidationErrorException;
}
