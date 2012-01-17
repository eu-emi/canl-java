/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.pkipath.bc;

import java.security.PublicKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import static eu.emi.security.authn.x509.helpers.pkipath.bc.FixedBCPKIXCertPathReviewer.RESOURCE_NAME;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEREnumerated;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuingDistributionPoint;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.i18n.ErrorBundle;
import org.bouncycastle.i18n.LocaleString;
import org.bouncycastle.i18n.filter.TrustedInput;
import org.bouncycastle.jce.provider.AnnotatedException;
import org.bouncycastle.jce.provider.RFC3280CertPathUtilities;
import org.bouncycastle.jce.provider.X509CRLEntryObject;
import org.bouncycastle.jce.provider.X509CRLObject;
import org.bouncycastle.x509.CertPathReviewerException;
import org.bouncycastle.x509.ExtendedPKIXParameters;

import eu.emi.security.authn.x509.CrlCheckingMode;
import eu.emi.security.authn.x509.ValidationErrorCode;
import eu.emi.security.authn.x509.helpers.pkipath.ExtPKIXParameters;

public class RFC3280CertPathUtilitiesHelper extends RFC3280CertPathUtilities
{

	/**
	 * Checks a certificate if it is revoked.
	 * 
	 * @param paramsPKIX PKIX parameters.
	 * @param cert Certificate to check if it is revoked.
	 * @param validDate The date when the certificate revocation status
	 *                should be checked.
	 * @param sign The issuer certificate of the certificate
	 *                <code>cert</code>.
	 * @param workingPublicKey The public key of the issuer certificate
	 *                <code>sign</code>.
	 * @param certPathCerts The certificates of the certification path.
	 * @throws AnnotatedException if the certificate is revoked or the
	 *                 status cannot be checked or some error occurs.
	 */
	protected static void localCheckCRLs(ExtPKIXParameters paramsPKIX, X509Certificate cert,
			Date validDate, X509Certificate sign, PublicKey workingPublicKey,
			List certPathCerts) throws SimpleValidationErrorException
	{
		SimpleValidationErrorException lastException = null;
		CRLDistPoint crldp = null;
		try
		{
			crldp = CRLDistPoint.getInstance(CertPathValidatorUtilities
					.getExtensionValue(cert,
						RFC3280CertPathUtilities.CRL_DISTRIBUTION_POINTS));
		} catch (Exception e)
		{
			throw new SimpleValidationErrorException(ValidationErrorCode.crlDistPtExtError, e); 
		}
		try
		{
			CertPathValidatorUtilities.addAdditionalStoresFromCRLDistributionPoint(crldp,
						paramsPKIX);
		} catch (AnnotatedException e)
		{
			throw new SimpleValidationErrorException(ValidationErrorCode.crlDistPtExtError, e); 
		}
		CertStatus certStatus = new CertStatus();
		ReasonsMask reasonsMask = new ReasonsMask();

		boolean validCrlFound = false;
		// for each distribution point
		if (crldp != null)
		{
			DistributionPoint dps[] = null;
			try
			{
				dps = crldp.getDistributionPoints();
			} catch (Exception e)
			{
				throw new SimpleValidationErrorException(
					ValidationErrorCode.crlDistPtExtError, e); 
			}
			if (dps != null)
			{
				for (int i = 0; i < dps.length
						&& certStatus.getCertStatus() == CertStatus.UNREVOKED
						&& !reasonsMask.isAllReasons(); i++)
				{
					ExtendedPKIXParameters paramsPKIXClone = (ExtendedPKIXParameters) paramsPKIX
							.clone();
					try
					{
						checkCRL(dps[i],
							paramsPKIXClone,
							cert,
							validDate,
							sign,
							workingPublicKey,
							certStatus,
							reasonsMask,
							certPathCerts);
						validCrlFound = true;
					} catch (SimpleValidationErrorException e)
					{
						lastException = e;
					}
				}
			}
		}

		/*
		 * If the revocation status has not been determined, repeat the
		 * process above with any available CRLs not specified in a
		 * distribution point but issued by the certificate issuer.
		 */

		if (certStatus.getCertStatus() == CertStatus.UNREVOKED
				&& !reasonsMask.isAllReasons())
		{
			try
			{
				/*
				 * assume a DP with both the reasons and the
				 * cRLIssuer fields omitted and a distribution
				 * point name of the certificate issuer.
				 */
				DERObject issuer = null;
				try
				{
					issuer = new ASN1InputStream(CertPathValidatorUtilities
							.getEncodedIssuerPrincipal(cert)
							.getEncoded()).readObject();
				} catch (Exception e)
				{
				            throw new SimpleValidationErrorException(ValidationErrorCode.crlIssuerException, e);
				}
				DistributionPoint dp = new DistributionPoint(
						new DistributionPointName(
								0,
								new GeneralNames(
										new GeneralName(
												GeneralName.directoryName,
												issuer))),
						null, null);
				ExtendedPKIXParameters paramsPKIXClone = (ExtendedPKIXParameters) paramsPKIX
						.clone();
				checkCRL(dp,
					paramsPKIXClone,
					cert,
					validDate,
					sign,
					workingPublicKey,
					certStatus,
					reasonsMask,
					certPathCerts);
				validCrlFound = true;
			} catch (SimpleValidationErrorException e)
			{
				lastException = e;
			}
		}

		if (!validCrlFound)
			throw lastException;
		if (certStatus.getCertStatus() != CertStatus.UNREVOKED)
		{
			LocaleString ls = new LocaleString(RESOURCE_NAME, crlReasons[certStatus.getCertStatus()]);
			throw new SimpleValidationErrorException(ValidationErrorCode.certRevoked,
				new TrustedInput(certStatus.getRevocationDate()), ls);
		}
		if (!reasonsMask.isAllReasons()
				&& certStatus.getCertStatus() == CertStatus.UNREVOKED)
		{
			certStatus.setCertStatus(CertStatus.UNDETERMINED);
		}
		if (certStatus.getCertStatus() == CertStatus.UNDETERMINED && 
				paramsPKIX.getCrlMode().equals(CrlCheckingMode.REQUIRE))
		{
		            throw new SimpleValidationErrorException(ValidationErrorCode.noValidCrlFound);
		}
	}

	/**
	 * Checks a distribution point for revocation information for the
	 * certificate <code>cert</code>.
	 * 
	 * @param dp The distribution point to consider.
	 * @param paramsPKIX PKIX parameters.
	 * @param cert Certificate to check if it is revoked.
	 * @param validDate The date when the certificate revocation status
	 *                should be checked.
	 * @param defaultCRLSignCert The issuer certificate of the certificate
	 *                <code>cert</code>.
	 * @param defaultCRLSignKey The public key of the issuer certificate
	 *                <code>defaultCRLSignCert</code>.
	 * @param certStatus The current certificate revocation status.
	 * @param reasonMask The reasons mask which is already checked.
	 * @param certPathCerts The certificates of the certification path.
	 * @throws AnnotatedException if the certificate is revoked or the
	 *                 status cannot be checked or some error occurs.
	 */
	private static void checkCRL(DistributionPoint dp, ExtendedPKIXParameters paramsPKIX,
			X509Certificate cert, Date validDate, X509Certificate defaultCRLSignCert,
			PublicKey defaultCRLSignKey, CertStatus certStatus, ReasonsMask reasonMask,
			List certPathCerts) throws SimpleValidationErrorException
	{
		Date currentDate = new Date(System.currentTimeMillis());
		if (validDate.getTime() > currentDate.getTime())
		{
			throw new IllegalArgumentException("CRL validation time is in future: " + validDate);
		}

		// (a)
		/*
		 * We always get timely valid CRLs, so there is no step (a) (1).
		 * "locally cached" CRLs are assumed to be in getStore(),
		 * additional CRLs must be enabled in the ExtendedPKIXParameters
		 * and are in getAdditionalStore()
		 */

		Set crls = CertPathValidatorUtilities.getCompleteCRLs2(dp,
			cert,
			currentDate,
			paramsPKIX);
		boolean validCrlFound = false;
		SimpleValidationErrorException lastException = null;
		Iterator crl_iter = crls.iterator();

		while (crl_iter.hasNext() && certStatus.getCertStatus() == CertStatus.UNREVOKED
				&& !reasonMask.isAllReasons())
		{
			try
			{
				X509CRL crl = (X509CRL) crl_iter.next();

				// (d)
				ReasonsMask interimReasonsMask = processCRLD2(crl, dp);

				// (e)
				/*
				 * The reasons mask is updated at the end, so
				 * only valid CRLs can update it. If this CRL
				 * does not contain new reasons it must be
				 * ignored.
				 */
				if (!interimReasonsMask.hasNewReasons(reasonMask))
				{
					continue;
				}

				// (f)
				Set keys = RFC3280CertPathUtilities.processCRLF(crl,
					cert,
					defaultCRLSignCert,
					defaultCRLSignKey,
					paramsPKIX,
					certPathCerts);
				// (g)
				PublicKey key = processCRLG2(crl, keys);

				X509CRL deltaCRL = null;

				if (paramsPKIX.isUseDeltasEnabled())
				{
					// get delta CRLs
					Set deltaCRLs = CertPathValidatorUtilities
							.getDeltaCRLs2(currentDate, paramsPKIX, crl);
					// we only want one valid delta CRL
					// (h)
					deltaCRL = processCRLH2(deltaCRLs, key);
				}

				/*
				 * CRL must be be valid at the current time, not
				 * the validation time. If a certificate is
				 * revoked with reason keyCompromise,
				 * cACompromise, it can be used for forgery,
				 * also for the past. This reason may not be
				 * contained in older CRLs.
				 */

				/*
				 * in the chain model signatures stay valid also
				 * after the certificate has been expired, so
				 * they do not have to be in the CRL validity
				 * time
				 */

				if (paramsPKIX.getValidityModel() != ExtendedPKIXParameters.CHAIN_VALIDITY_MODEL)
				{
					/*
					 * if a certificate has expired, but was
					 * revoked, it is not more in the CRL,
					 * so it would be regarded as valid if
					 * the first check is not done
					 */
					if (cert.getNotAfter().getTime() < crl.getThisUpdate()
							.getTime())
					{
						throw new SimpleValidationErrorException(ValidationErrorCode.noValidCrlFound);
					}
				}

				RFC3280CertPathUtilities.processCRLB1(dp, cert, crl);

				// (b) (2)
				RFC3280CertPathUtilities.processCRLB2(dp, cert, crl);

				// (c)
				RFC3280CertPathUtilities.processCRLC(deltaCRL, crl, paramsPKIX);

				// (i)
				processCRLI(validDate, deltaCRL, cert, certStatus, paramsPKIX);

				// (j)
				processCRLJ(validDate, crl, cert, certStatus);

				// (k)
				if (certStatus.getCertStatus() == CRLReason.removeFromCRL)
				{
					certStatus.setCertStatus(CertStatus.UNREVOKED);
				}

				// update reasons mask
				reasonMask.addReasons(interimReasonsMask);

				Set criticalExtensions = crl.getCriticalExtensionOIDs();
				if (criticalExtensions != null)
				{
					criticalExtensions = new HashSet(criticalExtensions);
					criticalExtensions.remove(X509Extensions.IssuingDistributionPoint.getId());
					criticalExtensions.remove(X509Extensions.DeltaCRLIndicator.getId());

					if (!criticalExtensions.isEmpty())
					{
						throw new SimpleValidationErrorException(ValidationErrorCode.crlUnknownCritExt, 
							criticalExtensions.iterator().next());
					}
				}

				if (deltaCRL != null)
				{
					criticalExtensions = deltaCRL.getCriticalExtensionOIDs();
					if (criticalExtensions != null)
					{
						criticalExtensions = new HashSet(criticalExtensions);
						criticalExtensions.remove(X509Extensions.IssuingDistributionPoint.getId());
						criticalExtensions.remove(X509Extensions.DeltaCRLIndicator.getId());
						if (!criticalExtensions.isEmpty())
						{
							throw new SimpleValidationErrorException(ValidationErrorCode.crlUnknownCritExt, 
								criticalExtensions.iterator().next());
						}
					}
				}

				validCrlFound = true;
			} catch (SimpleValidationErrorException e)
			{
				lastException = e;
			} catch (AnnotatedException e)
			{
				// FIXME - this catch should be removed, mapping of erros in methods.
				lastException = new SimpleValidationErrorException(ValidationErrorCode.unknownMsg, e);
			}
		}
		if (!validCrlFound)
		{
			throw lastException;
		}
	}

	protected static X509CRL processCRLH2(Set<?> deltacrls, PublicKey key) throws SimpleValidationErrorException
	{
		try
		{
			return RFC3280CertPathUtilities.processCRLH(deltacrls, key);
		} catch (AnnotatedException e)
		{
			throw new SimpleValidationErrorException(ValidationErrorCode.crlVerifyFailed, e);
		}
	}

	protected static PublicKey processCRLG2(X509CRL crl, Set<?> keys) throws SimpleValidationErrorException
	{
		try
		{
			return RFC3280CertPathUtilities.processCRLG(crl, keys);
		} catch (AnnotatedException e)
		{
			throw new SimpleValidationErrorException(ValidationErrorCode.crlVerifyFailed, e);
		}
	}

	protected static void processCRLI(Date validDate, X509CRL deltacrl, Object cert,
			CertStatus certStatus, ExtendedPKIXParameters pkixParams) 
					throws SimpleValidationErrorException
	{
		if (pkixParams.isUseDeltasEnabled() && deltacrl != null)
		{
			getCertStatus(validDate, deltacrl, cert, certStatus);
		}
	}

	protected static void processCRLJ(Date validDate, X509CRL completecrl, Object cert,
			CertStatus certStatus) throws SimpleValidationErrorException
	{
		if (certStatus.getCertStatus() == CertStatus.UNREVOKED)
		{
			getCertStatus(validDate, completecrl, cert, certStatus);
		}
	}

	protected static ReasonsMask processCRLD2(X509CRL crl, DistributionPoint dp) 
			throws SimpleValidationErrorException
	{
		IssuingDistributionPoint idp = null;
		try
		{
			idp = IssuingDistributionPoint
					.getInstance(CertPathValidatorUtilities
							.getExtensionValue(crl,
								RFC3280CertPathUtilities.ISSUING_DISTRIBUTION_POINT));
		} catch (Exception e)
		{
			throw new SimpleValidationErrorException(ValidationErrorCode.distrPtExtError, e);
		}
		// (d) (1)
		if (idp != null && idp.getOnlySomeReasons() != null && dp.getReasons() != null)
		{
			return new ReasonsMask(dp.getReasons().intValue())
					.intersect(new ReasonsMask(idp.getOnlySomeReasons()
							.intValue()));
		}
		// (d) (4)
		if ((idp == null || idp.getOnlySomeReasons() == null) && dp.getReasons() == null)
		{
			return ReasonsMask.allReasons;
		}
		// (d) (2) and (d)(3)
		return (dp.getReasons() == null ? ReasonsMask.allReasons : new ReasonsMask(dp
				.getReasons().intValue()))
				.intersect(idp == null ? ReasonsMask.allReasons : new ReasonsMask(
						idp.getOnlySomeReasons().intValue()));

	}

	protected static void getCertStatus(Date validDate, X509CRL crl, Object cert,
			CertStatus certStatus) throws SimpleValidationErrorException
	{
		// use BC X509CRLObject so that indirect CRLs are supported
		X509CRLObject bcCRL = null;
		try
		{
			bcCRL = new X509CRLObject(
					new CertificateList((ASN1Sequence) ASN1Sequence
							.fromByteArray(crl.getEncoded())));
		} catch (Exception e)
		{
			throw new SimpleValidationErrorException(ValidationErrorCode.unknownMsg, e);
		}
		// use BC X509CRLEntryObject, so that getCertificateIssuer() is
		// supported.
		X509CRLEntryObject crl_entry = (X509CRLEntryObject) bcCRL
				.getRevokedCertificate(CertPathValidatorUtilities
						.getSerialNumber(cert));
		if (crl_entry != null
				&& (CertPathValidatorUtilities.getEncodedIssuerPrincipal(cert)
						.equals(crl_entry.getCertificateIssuer()) || CertPathValidatorUtilities
						.getEncodedIssuerPrincipal(cert)
						.equals(crl.getIssuerX500Principal())))
		{
			DEREnumerated reasonCode = null;
			if (crl_entry.hasExtensions())
			{
				try
				{
					reasonCode = DEREnumerated
							.getInstance(CertPathValidatorUtilities
									.getExtensionValue(crl_entry,
										X509Extensions.ReasonCode
												.getId()));
				} catch (Exception e)
				{
					throw new SimpleValidationErrorException(ValidationErrorCode.crlReasonExtError, e);
				}
			}

			// for reason keyCompromise, caCompromise, aACompromise
			// or
			// unspecified
			if (!(validDate.getTime() < crl_entry.getRevocationDate().getTime())
					|| reasonCode == null
					|| reasonCode.getValue().intValue() == 0
					|| reasonCode.getValue().intValue() == 1
					|| reasonCode.getValue().intValue() == 2
					|| reasonCode.getValue().intValue() == 8)
			{

				// (i) or (j) (1)
				if (reasonCode != null)
				{
					certStatus.setCertStatus(reasonCode.getValue().intValue());
				}
				// (i) or (j) (2)
				else
				{
					certStatus.setCertStatus(CRLReason.unspecified);
				}
				certStatus.setRevocationDate(crl_entry.getRevocationDate());
			}
		}
	}

}
