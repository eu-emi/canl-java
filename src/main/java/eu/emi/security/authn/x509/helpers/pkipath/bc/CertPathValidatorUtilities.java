/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.pkipath.bc;

import static eu.emi.security.authn.x509.helpers.pkipath.bc.FixedBCPKIXCertPathReviewer.RESOURCE_NAME;

import java.math.BigInteger;
import java.security.cert.CertificateParsingException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.i18n.ErrorBundle;
import org.bouncycastle.jce.provider.AnnotatedException;
import org.bouncycastle.x509.CertPathReviewerException;
import org.bouncycastle.x509.ExtendedPKIXBuilderParameters;
import org.bouncycastle.x509.ExtendedPKIXParameters;
import org.bouncycastle.x509.X509AttributeCertificate;

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
	 * {@inheritDoc}
	 */
	protected static Set<?> getDeltaCRLs2(Date currentDate, ExtendedPKIXParameters paramsPKIX,
			X509CRL completeCRL) throws SimpleValidationErrorException
	{
		try
		{
			return org.bouncycastle.jce.provider.CertPathValidatorUtilities.getDeltaCRLs(
					currentDate, paramsPKIX, completeCRL);
		} catch (AnnotatedException e)
		{
			//TODO - proper errors
			throw new SimpleValidationErrorException(ValidationErrorCode.unknownMsg, e); 
		}
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
