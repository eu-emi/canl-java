/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.ocsp;

import java.security.cert.X509Certificate;

import eu.emi.security.authn.x509.OCSPCheckingMode;
import eu.emi.security.authn.x509.ValidationErrorCode;
import eu.emi.security.authn.x509.helpers.pkipath.SimpleValidationErrorException;
import eu.emi.security.authn.x509.helpers.revocation.RevocationChecker;
import eu.emi.security.authn.x509.helpers.revocation.RevocationStatus;

/**
 * Implementation of {@link RevocationChecker} using CRLs, the {@link OCSPVerifier} 
 * @author K. Benedyczak
 */
public class OCSPRevocationChecker implements RevocationChecker
{
	private OCSPVerifier verifier;
	private OCSPCheckingMode checkingMode;
	
	public OCSPRevocationChecker(OCSPVerifier verifier, OCSPCheckingMode checkingMode)
	{
		this.verifier = verifier;
		this.checkingMode = checkingMode;
	}

	@Override
	public RevocationStatus checkRevocation(X509Certificate certitifcate,
			X509Certificate issuer) throws SimpleValidationErrorException
	{
		if (checkingMode == OCSPCheckingMode.IGNORE)
			return RevocationStatus.unknown;		
		OCSPResult status;
		try
		{
			status = verifier.verify(certitifcate, issuer);
		} catch (SimpleValidationErrorException e)
		{
			if (checkingMode == OCSPCheckingMode.REQUIRE)
				throw e;
			return RevocationStatus.unknown;
		}
		if (status.getStatus() == OCSPResult.Status.revoked)
			throw new SimpleValidationErrorException(ValidationErrorCode.ocspCertRevoked, 
					status.getRevocationTime(), status.getRevocationReason());
		if (status.getStatus() == OCSPResult.Status.good)
			return RevocationStatus.verified;
		return RevocationStatus.unknown;
	}
}
