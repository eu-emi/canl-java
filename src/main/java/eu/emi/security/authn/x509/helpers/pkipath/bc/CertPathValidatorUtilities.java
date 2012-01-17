/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.pkipath.bc;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateParsingException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.provider.AnnotatedException;
import org.bouncycastle.x509.ExtendedPKIXBuilderParameters;
import org.bouncycastle.x509.ExtendedPKIXParameters;
import org.bouncycastle.x509.X509AttributeCertificate;
import org.bouncycastle.x509.X509CRLStoreSelector;

import eu.emi.security.authn.x509.ValidationErrorCode;

public class CertPathValidatorUtilities extends
		org.bouncycastle.jce.provider.CertPathValidatorUtilities
{
	/**
	 * {@inheritDoc}
	 */
	protected static TrustAnchor findTrustAnchor(X509Certificate cert, Set<?> trustAnchors,
			String sigProvider) throws AnnotatedException
	{
		return org.bouncycastle.jce.provider.CertPathValidatorUtilities.findTrustAnchor(
				cert, trustAnchors, sigProvider);
	}

	/**
	 * {@inheritDoc}
	 */
	protected static void addAdditionalStoresFromAltNames(X509Certificate cert,
			ExtendedPKIXParameters pkixParams) throws CertificateParsingException
	{
		org.bouncycastle.jce.provider.CertPathValidatorUtilities
				.addAdditionalStoresFromAltNames(cert, pkixParams);
	}

	/**
	 * {@inheritDoc}
	 */
	protected static Collection<?> findIssuerCerts(X509Certificate cert,
			ExtendedPKIXBuilderParameters pkixParams) throws AnnotatedException
	{
		return org.bouncycastle.jce.provider.CertPathValidatorUtilities.findIssuerCerts(
				cert, pkixParams);
	}

	/**
	 * {@inheritDoc}
	 */
	protected static Set<?> getCompleteCRLs2(DistributionPoint dp, Object cert, Date currentDate,
			ExtendedPKIXParameters paramsPKIX) throws SimpleValidationErrorException
	{
		try
		{
			return org.bouncycastle.jce.provider.CertPathValidatorUtilities.getCompleteCRLs(dp,
					cert, currentDate, paramsPKIX);
		} catch (AnnotatedException e)
		{
			if (e.getMessage().startsWith("No CRLs found for issuer"))
				throw new SimpleValidationErrorException(
					ValidationErrorCode.noValidCrlFound, e);
			else
				throw new SimpleValidationErrorException(
					ValidationErrorCode.crlExtractionError,
					e.getCause().getMessage(),e.getCause(),e.getCause().getClass().getName());
		}
	}

	/**
	 * Fetches delta CRLs according to RFC 3280 section 5.2.4. Copied to be
	 * able to fix bug in isDeltaCRL method.
	 * 
	 * @param currentDate The date for which the delta CRLs must be valid.
	 * @param paramsPKIX The extended PKIX parameters.
	 * @param completeCRL The complete CRL the delta CRL is for.
	 * @return A <code>Set</code> of <code>X509CRL</code>s with delta CRLs.
	 * @throws AnnotatedException if an exception occurs while picking the
	 *                 delta CRLs.
	 */
	protected static Set<X509CRL> getDeltaCRLs2(Date currentDate, ExtendedPKIXParameters paramsPKIX,
			X509CRL completeCRL) throws SimpleValidationErrorException
	{

		X509CRLStoreSelector deltaSelect = new X509CRLStoreSelector();

		// 5.2.4 (a)
		try
		{
			deltaSelect.addIssuerName(CertPathValidatorUtilities
					.getIssuerPrincipal(completeCRL).getEncoded());
		} catch (IOException e)
		{
			throw new SimpleValidationErrorException(ValidationErrorCode.crlIssuerException, e);
		}

		BigInteger completeCRLNumber = null;
		try
		{
			DERObject derObject = CertPathValidatorUtilities
					.getExtensionValue(completeCRL, CRL_NUMBER);
			if (derObject != null)
			{
				completeCRLNumber = CRLNumber.getInstance(derObject)
						.getPositiveValue();
			}
		} catch (Exception e)
		{
			throw new SimpleValidationErrorException(ValidationErrorCode.crlNbrExtError, e);
		}

		// 5.2.4 (b)
		byte[] idp = null;
		try
		{
			idp = completeCRL.getExtensionValue(ISSUING_DISTRIBUTION_POINT);
		} catch (Exception e)
		{
			throw new SimpleValidationErrorException(ValidationErrorCode.crlIssuerException, e);
		}

		// 5.2.4 (d)

		deltaSelect.setMinCRLNumber(completeCRLNumber == null ? null : completeCRLNumber
				.add(BigInteger.valueOf(1)));

		deltaSelect.setIssuingDistributionPoint(idp);
		deltaSelect.setIssuingDistributionPointEnabled(true);

		// 5.2.4 (c)
		deltaSelect.setMaxBaseCRLNumber(completeCRLNumber);

		// find delta CRLs
		Set<?> temp;
		try
		{
			temp = CRL_UTIL.findCRLs(deltaSelect, paramsPKIX, currentDate);
		} catch (AnnotatedException e)
		{
			throw new SimpleValidationErrorException(
				ValidationErrorCode.crlExtractionError, 
				(e.getCause() != null && e.getCause().getCause() != null) 
				? e.getCause().getCause() : e, e, e.getMessage());
		}

		Set<X509CRL> result = new HashSet<X509CRL>();

		for (Iterator<?> it = temp.iterator(); it.hasNext();)
		{
			X509CRL crl = (X509CRL) it.next();

			if (isDeltaCRL(crl))
			{
				result.add(crl);
			}
		}

		return result;
	}

	//fixed...
	@SuppressWarnings("deprecation")
	private static boolean isDeltaCRL(X509CRL crl)
	{
		Set<?> critical = crl.getCriticalExtensionOIDs();

		return critical != null && critical.contains(X509Extensions.DeltaCRLIndicator.getId());
	}

	/**
	 * {@inheritDoc}
	 */
	protected static DERObject getExtensionValue(java.security.cert.X509Extension ext,
			String oid) throws AnnotatedException
	{
		return org.bouncycastle.jce.provider.CertPathValidatorUtilities.getExtensionValue(
				ext, oid);
	}

	/**
	 * {@inheritDoc}
	 */
	protected static void addAdditionalStoresFromCRLDistributionPoint(CRLDistPoint crldp,
			ExtendedPKIXParameters pkixParams) throws AnnotatedException
	{
		org.bouncycastle.jce.provider.CertPathValidatorUtilities
				.addAdditionalStoresFromCRLDistributionPoint(crldp, pkixParams);
	}
	
	    public static BigInteger getSerialNumber(
		            Object cert)
		    {
		        if (cert instanceof X509Certificate)
		        {
		            return ((X509Certificate) cert).getSerialNumber();
		        }
		        else
		        {
		            return ((X509AttributeCertificate) cert).getSerialNumber();
		        }
		    }
	    
	    protected static X500Principal getEncodedIssuerPrincipal(
			        Object cert)
			    {
		    return org.bouncycastle.jce.provider.CertPathValidatorUtilities.getEncodedIssuerPrincipal(cert);
			    }
}
