/*
 * This class is copied from the BouncyCastle library, version 1.46.
 * See FixedBCPKIXCertPathReviewer in this package for extra information
 * 
 * Of course code is licensed and copyrighted by the BC:
 * 
 * 
Copyright (c) 2000 - 2011 The Legion Of The Bouncy Castle (http://www.bouncycastle.org)

Permission is hereby granted, free of charge, to any person obtaining a copy of this 
software and associated documentation files (the "Software"), to deal in the Software
without restriction, including without limitation the rights to use, copy, modify, merge,
publish, distribute, sublicense, and/or sell copies of the Software, and to permit
persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or
substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, 
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR 
PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE
FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, 
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR 
OTHER DEALINGS IN THE SOFTWARE.
 *  
 */
package eu.emi.security.authn.x509.helpers.pkipath.bc;

import java.math.BigInteger;
import java.security.cert.CertificateParsingException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.jce.provider.AnnotatedException;
import org.bouncycastle.x509.ExtendedPKIXBuilderParameters;
import org.bouncycastle.x509.ExtendedPKIXParameters;
import org.bouncycastle.x509.X509AttributeCertificate;

import eu.emi.security.authn.x509.ValidationErrorCode;
import eu.emi.security.authn.x509.helpers.pkipath.SimpleValidationErrorException;

/**
 * Exposes otherwise hidden methods from {@link CertPathValidatorUtilities} plus in some
 * cases fixes bugs plus produces errors in the desired format.
 * @author K. Benedyczak
 */
public class CertPathValidatorUtilities extends
		org.bouncycastle.jce.provider.CertPathValidatorUtilities
{
	public static TrustAnchor findTrustAnchor2(X509Certificate cert, Set<?> trustAnchors,
			String sigProvider) throws AnnotatedException
	{
		return org.bouncycastle.jce.provider.CertPathValidatorUtilities
				.findTrustAnchor(cert, trustAnchors, sigProvider);
	}

	public static void addAdditionalStoresFromAltNames(X509Certificate cert,
			ExtendedPKIXParameters pkixParams) throws CertificateParsingException
	{
		org.bouncycastle.jce.provider.CertPathValidatorUtilities
				.addAdditionalStoresFromAltNames(cert, pkixParams);
	}

	public static Collection<?> findIssuerCerts(X509Certificate cert,
			ExtendedPKIXBuilderParameters pkixParams) throws AnnotatedException
	{
		return org.bouncycastle.jce.provider.CertPathValidatorUtilities
				.findIssuerCerts(cert, pkixParams);
	}

	protected static Set<?> getCompleteCRLs2(DistributionPoint dp, X509Certificate cert,
			Date currentDate, ExtendedPKIXParameters paramsPKIX) throws SimpleValidationErrorException
	{
		try
		{
			return org.bouncycastle.jce.provider.CertPathValidatorUtilities
					.getCompleteCRLs(dp, cert, currentDate, paramsPKIX);
		} catch (AnnotatedException e)
		{
			if (e.getMessage().startsWith("No CRLs found for issuer"))
			{
				//workaround - in case when cert notOnOrAfter < nextUpdate of CRL BC
				//returns no CRL even if one is found. We try to detect this by changing error
				//for expired certificates (for which this situation is more then likely) and
				//provide a better error.
				if (cert.getNotAfter().after(currentDate))
					throw new SimpleValidationErrorException(
						ValidationErrorCode.noValidCrlFound, e);
				else
					throw new SimpleValidationErrorException(
						ValidationErrorCode.noCrlForExpiredCert, e);
				
			} else
				throw new SimpleValidationErrorException(
						ValidationErrorCode.crlExtractionError, e
								.getCause().getMessage(),
						e.getCause(), e.getCause().getClass().getName());
		}
	}

	/**
	 * Fetches delta CRLs according to RFC 3280 section 5.2.4.
	 * 
	 * @param currentDate The date for which the delta CRLs must be valid.
	 * @param paramsPKIX The extended PKIX parameters.
	 * @param completeCRL The complete CRL the delta CRL is for.
	 * @return A <code>Set</code> of <code>X509CRL</code>s with delta CRLs.
	 * @throws AnnotatedException if an exception occurs while picking the
	 *                 delta CRLs.
	 */
	protected static Set<X509CRL> getDeltaCRLs2(Date currentDate,
			ExtendedPKIXParameters paramsPKIX, X509CRL completeCRL) throws SimpleValidationErrorException
	{
		try
		{
			return getDeltaCRLs(currentDate, paramsPKIX, completeCRL);
		} catch (AnnotatedException e)
		{
			throw new SimpleValidationErrorException(
					ValidationErrorCode.crlDeltaProblem, e.getMessage(),
					e.getCause(), e.getCause().getClass().getName());
		}
	}

	protected static ASN1Primitive getExtensionValue(java.security.cert.X509Extension ext,
			String oid) throws AnnotatedException
	{
		return org.bouncycastle.jce.provider.CertPathValidatorUtilities
				.getExtensionValue(ext, oid);
	}

	protected static void addAdditionalStoresFromCRLDistributionPoint(CRLDistPoint crldp,
			ExtendedPKIXParameters pkixParams) throws AnnotatedException
	{
		org.bouncycastle.jce.provider.CertPathValidatorUtilities
				.addAdditionalStoresFromCRLDistributionPoint(crldp, pkixParams);
	}

	public static BigInteger getSerialNumber(Object cert)
	{
		if (cert instanceof X509Certificate)
		{
			return ((X509Certificate) cert).getSerialNumber();
		} else
		{
			return ((X509AttributeCertificate) cert).getSerialNumber();
		}
	}

	protected static X500Principal getEncodedIssuerPrincipal(Object cert)
	{
		return org.bouncycastle.jce.provider.CertPathValidatorUtilities
				.getEncodedIssuerPrincipal(cert);
	}
}
