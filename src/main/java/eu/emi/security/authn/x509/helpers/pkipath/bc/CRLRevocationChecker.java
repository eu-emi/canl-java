/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.pkipath.bc;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

import eu.emi.security.authn.x509.CrlCheckingMode;
import eu.emi.security.authn.x509.ValidationErrorCode;
import eu.emi.security.authn.x509.helpers.pkipath.ExtPKIXParameters;
import eu.emi.security.authn.x509.helpers.pkipath.SimpleValidationErrorException;
import eu.emi.security.authn.x509.helpers.revocation.RevocationChecker;
import eu.emi.security.authn.x509.helpers.revocation.RevocationStatus;

/**
 * Implementation of {@link RevocationChecker} using CRLs, the {@link RFC3280CertPathUtilitiesHelper}.
 * @author K. Benedyczak
 */
public class CRLRevocationChecker implements RevocationChecker
{
	private ExtPKIXParameters paramsPKIX;
	private Date validDate;
	private PublicKey workingPublicKey;
	private List<?> certificates;
	private CrlCheckingMode checkingMode;
	
	public CRLRevocationChecker(ExtPKIXParameters paramsPKIX, Date validDate, PublicKey workingPublicKey,
			List<?> certificates, CrlCheckingMode checkingMode)
	{
		this.paramsPKIX = paramsPKIX;
		this.validDate = validDate;
		this.workingPublicKey = workingPublicKey;
		this.certificates = certificates;
		this.checkingMode = checkingMode;
	}

	@Override
	public RevocationStatus checkRevocation(X509Certificate certitifcate,
			X509Certificate issuer) throws SimpleValidationErrorException
	{
		if (checkingMode == CrlCheckingMode.IGNORE)
			return RevocationStatus.unknown;
		try
		{
			RFC3280CertPathUtilitiesHelper.checkCRLs2(paramsPKIX, certitifcate, validDate, 
				issuer, workingPublicKey, certificates);
		} catch (SimpleValidationErrorException e)
		{
			if (e.getCode() == ValidationErrorCode.noValidCrlFound && 
					checkingMode == CrlCheckingMode.IF_VALID)
				return RevocationStatus.unknown;
			throw e;
		}
		return RevocationStatus.verified;
	}
}
