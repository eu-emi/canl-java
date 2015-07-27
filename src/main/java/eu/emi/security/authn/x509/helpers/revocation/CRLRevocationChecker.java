/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.revocation;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

import org.bouncycastle.jcajce.util.BCJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;

import eu.emi.security.authn.x509.CrlCheckingMode;
import eu.emi.security.authn.x509.ValidationErrorCode;
import eu.emi.security.authn.x509.helpers.pkipath.ExtPKIXParameters2;
import eu.emi.security.authn.x509.helpers.pkipath.SimpleValidationErrorException;
import eu.emi.security.authn.x509.helpers.pkipath.bc.RFC3280CertPathUtilitiesCanl;

/**
 * Implementation of {@link RevocationChecker} using CRLs, the {@link RFC3280CertPathUtilitiesCanl}.
 * @author K. Benedyczak
 */
public class CRLRevocationChecker implements RevocationChecker
{
	private ExtPKIXParameters2 paramsPKIX;
	private Date validDate;
	private PublicKey workingPublicKey;
	private List<?> certificates;
	private CrlCheckingMode checkingMode;
	private JcaJceHelper jcaHelper;
	
	public CRLRevocationChecker(ExtPKIXParameters2 paramsPKIX, Date validDate, PublicKey workingPublicKey,
			List<?> certificates, CrlCheckingMode checkingMode)
	{
		this.paramsPKIX = paramsPKIX;
		this.validDate = validDate;
		this.workingPublicKey = workingPublicKey;
		this.certificates = certificates;
		this.checkingMode = checkingMode;
		this.jcaHelper = new BCJcaJceHelper();
	}

	@Override
	public RevocationStatus checkRevocation(X509Certificate certitifcate,
			X509Certificate issuer) throws SimpleValidationErrorException
	{
		if (checkingMode == CrlCheckingMode.IGNORE)
			return RevocationStatus.unknown;
		try
		{
			RFC3280CertPathUtilitiesCanl.checkCRLs2(paramsPKIX, certitifcate, validDate, 
				issuer, workingPublicKey, certificates, jcaHelper);
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
