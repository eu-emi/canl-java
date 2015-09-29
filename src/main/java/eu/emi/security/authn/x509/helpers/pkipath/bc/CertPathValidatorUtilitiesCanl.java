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
import java.security.cert.X509CRLSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.jcajce.PKIXCRLStore;
import org.bouncycastle.jcajce.PKIXCRLStoreSelector;
import org.bouncycastle.jcajce.PKIXCertStore;
import org.bouncycastle.jcajce.PKIXExtendedBuilderParameters;
import org.bouncycastle.jcajce.PKIXExtendedParameters;
import org.bouncycastle.jce.provider.AnnotatedException;
import org.bouncycastle.x509.X509AttributeCertificate;

import eu.emi.security.authn.x509.ValidationErrorCode;
import eu.emi.security.authn.x509.helpers.pkipath.SimpleValidationErrorException;

/**
 * Exposes otherwise hidden methods from {@link CertPathValidatorUtilitiesCanl} plus in some
 * cases fixes bugs plus produces errors in the desired format.
 * @author K. Benedyczak
 */
public class CertPathValidatorUtilitiesCanl extends CertPathValidatorUtilities
{
	/*
	 * Delegates to BC method, added to be public. 
	 */
	public static TrustAnchor findTrustAnchorPublic(X509Certificate cert, Set<?> trustAnchors,
			String sigProvider) throws AnnotatedException
	{
		return CertPathValidatorUtilities.findTrustAnchor(cert, trustAnchors, sigProvider);
	}

	public static Collection<?> findIssuerCerts(X509Certificate cert,
			PKIXExtendedBuilderParameters pkixParams) throws AnnotatedException
	{
		@SuppressWarnings("rawtypes")
		List<PKIXCertStore> stores = new ArrayList<PKIXCertStore>();

                stores.addAll(pkixParams.getBaseParameters().getCertificateStores());
                // add additional X.509 stores from locations in certificate
                try
                {
                    stores.addAll(CertPathValidatorUtilities.getAdditionalStoresFromAltNames(
                		    cert.getExtensionValue(Extension.issuerAlternativeName.getId()), 
                		    pkixParams.getBaseParameters().getNamedCertificateStoreMap()));
                }
                catch (CertificateParsingException e)
                {
                	//OK, we ignore those
                }
		return CertPathValidatorUtilities.findIssuerCerts(cert, pkixParams.getBaseParameters().
				getCertStores(), stores);
	}

	protected static Set<?> getCompleteCRLs2(DistributionPoint dp, X509Certificate cert,
			Date currentDate, PKIXExtendedParameters paramsPKIX) throws SimpleValidationErrorException
	{
		try
		{
			return getCompleteCRLs(dp, cert, currentDate, paramsPKIX);
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
	 * As {@link CertPathValidatorUtilities#getCompleteCRLs(DistributionPoint, Object, Date, PKIXExtendedParameters)}
	 * but it returns also expired CRLs.
	 * @param dp
	 * @param cert
	 * @param currentDate
	 * @param paramsPKIX
	 * @return
	 * @throws AnnotatedException
	 */
	protected static Set getCompleteCRLs(DistributionPoint dp, Object cert,
			Date currentDate, PKIXExtendedParameters paramsPKIX)
					throws AnnotatedException
	{
		X509CRLSelector baseCrlSelect = new X509CRLSelector();

		try
		{
			Set issuers = new HashSet();

			issuers.add(PrincipalUtils.getEncodedIssuerPrincipal(cert));

			CertPathValidatorUtilities.getCRLIssuersFromDistributionPoint(dp, issuers, baseCrlSelect);
		}
		catch (AnnotatedException e)
		{
			throw new AnnotatedException(
					"Could not get issuer information from distribution point.", e);
		}

		if (cert instanceof X509Certificate)
		{
			baseCrlSelect.setCertificateChecking((X509Certificate)cert);
		}

		PKIXCRLStoreSelector crlSelect = new PKIXCRLStoreSelector.Builder(baseCrlSelect).setCompleteCRLEnabled(true).build();

		Date validityDate = new Date(0);

		Set crls = CRL_UTIL.findCRLs(crlSelect, validityDate, paramsPKIX.getCertStores(), paramsPKIX.getCRLStores());

		checkCRLsNotEmpty(crls, cert);

		return crls;
	}

	
	
	/**
	 * Fetches delta CRLs according to RFC 3280 section 5.2.4.
	 * 
	 * @param currentDate The date for which the delta CRLs must be valid.
	 * @param paramsPKIX The extended PKIX parameters.
	 * @param completeCRL The complete CRL the delta CRL is for.
	 * @return A <code>Set</code> of <code>X509CRL</code>s with delta CRLs.
	 * @throws SimpleValidationErrorException if an exception occurs while picking the
	 *                 delta CRLs.
	 */
	@SuppressWarnings("unchecked")
	protected static Set<X509CRL> getDeltaCRLs2(Date currentDate,
			PKIXExtendedParameters paramsPKIX, X509CRL completeCRL) throws SimpleValidationErrorException
	{
		try
		{
			return getDeltaCRLs(currentDate, completeCRL, 
					paramsPKIX.getCertStores(), 
					paramsPKIX.getCRLStores());
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
		return CertPathValidatorUtilities.getExtensionValue(ext, oid);
	}

	/*
	 * simplifies usage, probably can be removed TODO
	 */
	@SuppressWarnings("rawtypes")
	protected static List<PKIXCRLStore> getAdditionalStoresFromCRLDistributionPoint(CRLDistPoint crldp,
			PKIXExtendedBuilderParameters pkixParams) throws AnnotatedException
	{
		return CertPathValidatorUtilities.getAdditionalStoresFromCRLDistributionPoint(crldp, 
						pkixParams.getBaseParameters().getNamedCRLStoreMap());
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
}
