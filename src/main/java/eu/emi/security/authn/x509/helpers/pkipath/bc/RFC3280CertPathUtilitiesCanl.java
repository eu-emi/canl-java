/*
 * This class is copied from the BouncyCastle library, version 1.46.
 * See FixedBCPKIXCertPathReviewer in this package for extra information.
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

import java.security.PublicKey;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuingDistributionPoint;
import org.bouncycastle.i18n.filter.TrustedInput;
import org.bouncycastle.jcajce.PKIXCRLStore;
import org.bouncycastle.jcajce.PKIXExtendedParameters;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jce.provider.AnnotatedException;
import org.bouncycastle.jce.provider.X509CRLObject;

import eu.emi.security.authn.x509.ValidationErrorCode;
import eu.emi.security.authn.x509.helpers.pkipath.ExtPKIXParameters2;
import eu.emi.security.authn.x509.helpers.pkipath.SimpleValidationErrorException;

/**
 * This class exposes the BC's JCA implementation of the {@link RFC3280CertPathUtilities}.
 * It was done to: fix its bugs (only one or two, should be OK in BC 1.47) and 
 * to have errors consumable by the rest of this library (most of the code).
 * @author K. Benedyczak (modifications)
 */
public class RFC3280CertPathUtilitiesCanl extends RFC3280CertPathUtilities
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
	public static void checkCRLs2(ExtPKIXParameters2 paramsPKIX, X509Certificate cert,
			Date validDate, X509Certificate sign, PublicKey workingPublicKey,
			List<?> certPathCerts, JcaJceHelper jcaHelper) throws SimpleValidationErrorException
	{
		SimpleValidationErrorException lastException = null;
		CRLDistPoint crldp = null;
		try
		{
			crldp = CRLDistPoint.getInstance(CertPathValidatorUtilitiesCanl
					.getExtensionValue(cert,
						RFC3280CertPathUtilities.CRL_DISTRIBUTION_POINTS));
		} catch (Exception e)
		{
			throw new SimpleValidationErrorException(ValidationErrorCode.crlDistPtExtError, e); 
		}
		

		PKIXExtendedParameters.Builder paramsBldr = new PKIXExtendedParameters.Builder(
				paramsPKIX.getBaseParameters());
		try
		{
			@SuppressWarnings("rawtypes")
			List<PKIXCRLStore> extras = CertPathValidatorUtilities.getAdditionalStoresFromCRLDistributionPoint(crldp, 
					paramsPKIX.getBaseParameters().getNamedCRLStoreMap());
			for (@SuppressWarnings("rawtypes") PKIXCRLStore store: extras)
			{
				paramsBldr.addCRLStore(store);
			}
		}
		catch (AnnotatedException e)
		{
			throw new SimpleValidationErrorException(ValidationErrorCode.crlDistPtExtError, e);
		}

		CertStatus certStatus = new CertStatus();
		ReasonsMask reasonsMask = new ReasonsMask();
		PKIXExtendedParameters finalParams = paramsBldr.build();
		       
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
					try
					{
						checkCRL(dps[i],
							finalParams,
							cert,
							validDate,
							sign,
							workingPublicKey,
							certStatus,
							reasonsMask,
							certPathCerts,
							jcaHelper);
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
				ASN1Primitive issuer = null;
				try
				{
					issuer = new ASN1InputStream(PrincipalUtils.getEncodedIssuerPrincipal(
							cert).getEncoded()).readObject();
				} catch (Exception e)
				{
				            throw new SimpleValidationErrorException(ValidationErrorCode.crlIssuerException, e);
				}
				DistributionPoint dp = new DistributionPoint(
						new DistributionPointName(0,
						new GeneralNames(new GeneralName(GeneralName.directoryName, issuer))), null, null);
				checkCRL(dp,
					paramsPKIX.getBaseParameters(),
					cert,
					validDate,
					sign,
					workingPublicKey,
					certStatus,
					reasonsMask,
					certPathCerts,
					jcaHelper);
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
			throw new SimpleValidationErrorException(ValidationErrorCode.certRevoked,
				new TrustedInput(certStatus.getRevocationDate()), 
				crlReasons[certStatus.getCertStatus()]);
		}
		if (!reasonsMask.isAllReasons()
				&& certStatus.getCertStatus() == CertStatus.UNREVOKED)
		{
			certStatus.setCertStatus(CertStatus.UNDETERMINED);
		}
		if (certStatus.getCertStatus() == CertStatus.UNDETERMINED)
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
	private static void checkCRL(DistributionPoint dp, PKIXExtendedParameters paramsPKIX,
			X509Certificate cert, Date validDate, X509Certificate defaultCRLSignCert,
			PublicKey defaultCRLSignKey, CertStatus certStatus, ReasonsMask reasonMask,
			List<?> certPathCerts, JcaJceHelper jcaHelper) throws SimpleValidationErrorException
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

		Set<?> crls = CertPathValidatorUtilitiesCanl.getCompleteCRLs2(dp,
			cert,
			currentDate,
			paramsPKIX);
		boolean validCrlFound = false;
		SimpleValidationErrorException lastException = null;
		Iterator<?> crl_iter = crls.iterator();

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
				Set<?> keys = processCRLF2(crl,
					cert,
					defaultCRLSignCert,
					defaultCRLSignKey,
					paramsPKIX,
					certPathCerts, 
					jcaHelper);
				// (g)
				PublicKey key = processCRLG2(crl, keys);

				X509CRL deltaCRL = null;
		                Date validityDate = currentDate;

		                if (paramsPKIX.getDate() != null)
		                {
		                    validityDate = paramsPKIX.getDate();
		                }
		                
				if (paramsPKIX.isUseDeltasEnabled())
				{
					// get delta CRLs
					Set<?> deltaCRLs = CertPathValidatorUtilitiesCanl.getDeltaCRLs2(validityDate, 
									paramsPKIX, crl);
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

				if (paramsPKIX.getValidityModel() != PKIXExtendedParameters.CHAIN_VALIDITY_MODEL)
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

				processCRLB1_2(dp, cert, crl);

				// (b) (2)
				processCRLB2_2(dp, cert, crl);

				// (c)
				processCRLC2(deltaCRL, crl, paramsPKIX);

				// (i)
				processCRLI2(validDate, deltaCRL, cert, certStatus, paramsPKIX);

				// (j)
				processCRLJ2(validDate, crl, cert, certStatus);

				// (k)
				if (certStatus.getCertStatus() == CRLReason.removeFromCRL)
				{
					certStatus.setCertStatus(CertStatus.UNREVOKED);
				}

				// update reasons mask
				reasonMask.addReasons(interimReasonsMask);

				Set<String> criticalExtensions = crl.getCriticalExtensionOIDs();
				if (criticalExtensions != null)
				{
					criticalExtensions = new HashSet<String>(criticalExtensions);
					criticalExtensions.remove(Extension.issuingDistributionPoint.getId());
					criticalExtensions.remove(Extension.deltaCRLIndicator.getId());

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
						criticalExtensions = new HashSet<String>(criticalExtensions);
						criticalExtensions.remove(Extension.issuingDistributionPoint.getId());
						criticalExtensions.remove(Extension.deltaCRLIndicator.getId());
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
			}
		}
		if (!validCrlFound)
		{
			throw lastException;
		}
	}
	
	private static void processCRLB1_2(DistributionPoint dp, Object cert, X509CRL crl) 
			throws SimpleValidationErrorException
	{
		try
		{
			RFC3280CertPathUtilities.processCRLB1(dp, cert, crl);
		} catch (AnnotatedException e)
		{
			if (e.getMessage().startsWith("CRL issuer information from distribution point cannot be decoded"))
			{
				throw new SimpleValidationErrorException(
					ValidationErrorCode.crlIssuerException, e.getCause());
			} else if (e.getMessage().startsWith("Distribution point contains cRLIssuer field but CRL is not indirect"))
			{
				throw new SimpleValidationErrorException(
					ValidationErrorCode.distrPtExtError, e.getMessage());
			} else if (e.getMessage().startsWith("CRL issuer of CRL does not match CRL issuer of distribution point"))
			{
				throw new SimpleValidationErrorException(
					ValidationErrorCode.distrPtExtError, e.getMessage());
			} else if (e.getMessage().startsWith("Cannot find matching CRL issuer for certificate"))
			{
				throw new SimpleValidationErrorException(
					ValidationErrorCode.crlNoIssuerForDP);
			} else if (e.getMessage().startsWith("exception processing extension"))
			{
				throw new SimpleValidationErrorException(
					ValidationErrorCode.distrPtExtError, e.getCause());
			} else
			{
				throw new SimpleValidationErrorException(
					ValidationErrorCode.unknownMsg, e);
			}
		}
	}
	
	private static void processCRLB2_2(DistributionPoint dp, Object cert, X509CRL crl) 
			throws SimpleValidationErrorException
	{
		try
		{
			RFC3280CertPathUtilities.processCRLB2(dp, cert, crl);
		} catch (AnnotatedException e)
		{
			if (e.getMessage().startsWith("Issuing distribution point extension could not be decoded"))
			{
				throw new SimpleValidationErrorException(
					ValidationErrorCode.distrPtExtError, e.getCause());
			} else if (e.getMessage().startsWith("Could not read CRL issuer"))
			{
				throw new SimpleValidationErrorException(
					ValidationErrorCode.crlIssuerException, e);
			} else if (e.getMessage().startsWith("No match for certificate CRL issuing distribution point name to cRLIssuer CRL distribution point"))
			{
				throw new SimpleValidationErrorException(
					ValidationErrorCode.crlIDPAndDPMismatch);
			} else if (e.getMessage().startsWith("Either the cRLIssuer or the distributionPoint field must"))
			{
				throw new SimpleValidationErrorException(
					ValidationErrorCode.crlNoIssuerAndDP);
			} else if (e.getMessage().startsWith("Basic constraints extension could not be decoded"))
			{
				throw new SimpleValidationErrorException(
					ValidationErrorCode.crlBCExtError, e.getCause());
			} else if (e.getMessage().startsWith("CA Cert CRL only contains user certificates"))
			{
				throw new SimpleValidationErrorException(
					ValidationErrorCode.crlOnlyUserCert);
			} else if (e.getMessage().startsWith("End CRL only contains CA certificates"))
			{
				throw new SimpleValidationErrorException(
					ValidationErrorCode.crlOnlyCaCert);
			} else if (e.getMessage().startsWith("onlyContainsAttributeCerts boolean is asserted"))
			{
				throw new SimpleValidationErrorException(
					ValidationErrorCode.crlOnlyAttrCert);
			} else
			{
				throw new SimpleValidationErrorException(
					ValidationErrorCode.unknownMsg, e);
			}
		}
	}
	
	private static void processCRLC2(X509CRL deltaCRL, X509CRL completeCRL,
			PKIXExtendedParameters pkixParams) throws SimpleValidationErrorException
	{
		try
		{
			RFC3280CertPathUtilities.processCRLC(deltaCRL, completeCRL, pkixParams);
		} catch (AnnotatedException e)
		{
			if (e.getMessage().startsWith("Issuing distribution point extension"))
			{
				throw new SimpleValidationErrorException(
					ValidationErrorCode.distrPtExtError, e.getCause());
			} else if (e.getMessage().startsWith("Complete CRL issuer does not match delta CRL issuer"))
			{
				throw new SimpleValidationErrorException(
					ValidationErrorCode.crlDeltaProblem, e.getMessage());
			} else if (e.getMessage().startsWith("Issuing distribution point extension from delta CRL and complete CRL does not match"))
			{
				throw new SimpleValidationErrorException(
					ValidationErrorCode.crlDeltaProblem, e.getMessage());
			} else if (e.getMessage().startsWith("Authority key identifier extension could not be extracted from"))
			{
				throw new SimpleValidationErrorException(
					ValidationErrorCode.crlAKIExtError, e.getCause());
			} else if (e.getMessage().startsWith("CRL authority key identifier is null"))
			{
				throw new SimpleValidationErrorException(
					ValidationErrorCode.crlAKIExtError, e.getMessage());
			} else if (e.getMessage().startsWith("Delta CRL authority key identifier is null"))
			{
				throw new SimpleValidationErrorException(
					ValidationErrorCode.crlAKIExtError, e.getMessage());
			} else if (e.getMessage().startsWith("Delta CRL authority key identifier does not match complete CRL authority key identifier"))
			{
				throw new SimpleValidationErrorException(
					ValidationErrorCode.crlDeltaProblem, e.getMessage());
			} else
			{
				throw new SimpleValidationErrorException(
					ValidationErrorCode.unknownMsg, e);
			}
		}
	}

	private static Set<?> processCRLF2(X509CRL crl, Object cert,
			X509Certificate defaultCRLSignCert, PublicKey defaultCRLSignKey,
			PKIXExtendedParameters paramsPKIX, List<?> certPathCerts, JcaJceHelper helper) 
					throws SimpleValidationErrorException
	{
		try
		{
			return RFC3280CertPathUtilities.processCRLF(crl, cert, defaultCRLSignCert, 
				defaultCRLSignKey, paramsPKIX, certPathCerts, helper);
		} catch (AnnotatedException e)
		{
			if (e.getMessage().startsWith("Subject criteria for certificate selector to find issuer certificate for CRL could not be set"))
			{
				new RuntimeException(e.getMessage(), e);
			} else if (e.getMessage().startsWith("Issuer certificate for CRL cannot be searched"))
			{
				new RuntimeException(e.getMessage(), e);
			} else if (e.getMessage().startsWith("Internal error"))
			{
				throw new SimpleValidationErrorException(
					ValidationErrorCode.crlNoIssuerPublicKey, e.getCause());
			} else if (e.getMessage().startsWith("Public key of issuer certificate of CRL could not be retrieved"))
			{
				throw new SimpleValidationErrorException(
					ValidationErrorCode.crlNoIssuerPublicKey, e.getCause());
			} else if (e.getMessage().startsWith("Issuer certificate key usage extension does not permit CRL signing"))
			{
				throw new SimpleValidationErrorException(
					ValidationErrorCode.noCrlSigningPermited);
			} else if (e.getMessage().startsWith("Cannot find a valid issuer certificate"))
			{
				throw new SimpleValidationErrorException(
					ValidationErrorCode.crlNoIssuerPublicKey, e.getMessage());
			}
			throw new SimpleValidationErrorException(
					ValidationErrorCode.unknownMsg, e);
		}
	}

	private static X509CRL processCRLH2(Set<?> deltacrls, PublicKey key) 
			throws SimpleValidationErrorException
	{
		try
		{
			return RFC3280CertPathUtilities.processCRLH(deltacrls, key);
		} catch (AnnotatedException e)
		{
			throw new SimpleValidationErrorException(ValidationErrorCode.crlVerifyFailed, e);
		}
	}

	private static PublicKey processCRLG2(X509CRL crl, Set<?> keys) throws SimpleValidationErrorException
	{
		try
		{
			return RFC3280CertPathUtilities.processCRLG(crl, keys);
		} catch (AnnotatedException e)
		{
			throw new SimpleValidationErrorException(ValidationErrorCode.crlVerifyFailed, e);
		}
	}

	private static void processCRLI2(Date validDate, X509CRL deltacrl, Object cert,
			CertStatus certStatus, PKIXExtendedParameters pkixParams) 
					throws SimpleValidationErrorException
	{
		if (pkixParams.isUseDeltasEnabled() && deltacrl != null)
		{
			getCertStatus(validDate, deltacrl, cert, certStatus);
		}
	}

	private static void processCRLJ2(Date validDate, X509CRL completecrl, Object cert,
			CertStatus certStatus) throws SimpleValidationErrorException
	{
		if (certStatus.getCertStatus() == CertStatus.UNREVOKED)
		{
			getCertStatus(validDate, completecrl, cert, certStatus);
		}
	}

	private static ReasonsMask processCRLD2(X509CRL crl, DistributionPoint dp) 
			throws SimpleValidationErrorException
	{
		IssuingDistributionPoint idp = null;
		try
		{
			idp = IssuingDistributionPoint
					.getInstance(CertPathValidatorUtilitiesCanl
							.getExtensionValue(crl,
								RFC3280CertPathUtilities.ISSUING_DISTRIBUTION_POINT));
		} catch (Exception e)
		{
			throw new SimpleValidationErrorException(ValidationErrorCode.distrPtExtError, e);
		}
		// (d) (1)
		if (idp != null && idp.getOnlySomeReasons() != null && dp.getReasons() != null)
		{
			return new ReasonsMask(dp.getReasons())
					.intersect(new ReasonsMask(idp.getOnlySomeReasons()));
		}
		// (d) (4)
		if ((idp == null || idp.getOnlySomeReasons() == null) && dp.getReasons() == null)
		{
			return ReasonsMask.allReasons;
		}
		// (d) (2) and (d)(3)
		return (dp.getReasons() == null ? ReasonsMask.allReasons : new ReasonsMask(dp
				.getReasons()))
				.intersect(idp == null ? ReasonsMask.allReasons : new ReasonsMask(
						idp.getOnlySomeReasons()));

	}

	protected static void getCertStatus(Date validDate, X509CRL crl, Object cert,
			CertStatus certStatus) throws SimpleValidationErrorException
	{
		X509CRLEntry crl_entry = null;

		boolean isIndirect;
		try
		{
			isIndirect = X509CRLObject.isIndirectCRL(crl);
		} catch (CRLException exception)
		{
			throw new SimpleValidationErrorException(ValidationErrorCode.unknownMsg, exception);
		}

		if (isIndirect)
		{
			crl_entry = crl.getRevokedCertificate(CertPathValidatorUtilitiesCanl.getSerialNumber(cert));

			if (crl_entry == null)
			{
				return;
			}

			X500Principal certificateIssuer = crl_entry.getCertificateIssuer();

			X500Name certIssuer;
			if (certificateIssuer == null)
			{
				certIssuer = PrincipalUtils.getIssuerPrincipal(crl);
			} else
			{
				certIssuer = X500Name.getInstance(certificateIssuer.getEncoded());
			}

			if (!PrincipalUtils.getEncodedIssuerPrincipal(cert).equals(certIssuer))
			{
				return;
			}
		} else if (!PrincipalUtils.getEncodedIssuerPrincipal(cert).equals(
				PrincipalUtils.getIssuerPrincipal(crl)))
		{
			return; // not for our issuer, ignore
		} else
		{
			crl_entry = crl.getRevokedCertificate(CertPathValidatorUtilitiesCanl.getSerialNumber(cert));

			if (crl_entry == null)
			{
				return;
			}
		}

		ASN1Enumerated reasonCode = null;
		if (crl_entry.hasExtensions())
		{
			try
			{
				reasonCode = ASN1Enumerated.getInstance(CertPathValidatorUtilities
						.getExtensionValue(crl_entry,
								Extension.reasonCode.getId()));
			} catch (Exception e)
			{
				throw new SimpleValidationErrorException(ValidationErrorCode.crlReasonExtError, e);
			}
		}

		// for reason keyCompromise, caCompromise, aACompromise or
		// unspecified
		if (!(validDate.getTime() < crl_entry.getRevocationDate().getTime())
				|| reasonCode == null || reasonCode.getValue().intValue() == 0
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
	
	/*
	 * Code from pre 1-52 update of canl TODO - remove after tests of the new version
	private static void getCertStatus(Date validDate, X509CRL crl, Object cert,
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
				.getRevokedCertificate(CertPathValidatorUtilitiesCanl
						.getSerialNumber(cert));
		if (crl_entry != null
				&& (CertPathValidatorUtilitiesCanl.getEncodedIssuerPrincipal(cert)
						.equals(crl_entry.getCertificateIssuer()) || CertPathValidatorUtilitiesCanl
						.getEncodedIssuerPrincipal(cert)
						.equals(crl.getIssuerX500Principal())))
		{
			ASN1Enumerated reasonCode = null;
			if (crl_entry.hasExtensions())
			{
				try
				{
					reasonCode = ASN1Enumerated
							.getInstance(CertPathValidatorUtilitiesCanl
							.getExtensionValue(crl_entry,
							X509Extensions.ReasonCode.getId()));
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
*/
}
