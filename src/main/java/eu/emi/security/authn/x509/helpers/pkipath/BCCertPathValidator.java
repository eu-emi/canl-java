/*
 * Copyright (c) 2011 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.pkipath;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.i18n.ErrorBundle;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.CertPathReviewerException;
import org.bouncycastle.x509.PKIXCertPathReviewer;
import org.bouncycastle.x509.X509CertStoreSelector;

import eu.emi.security.authn.x509.RevocationParameters;
import eu.emi.security.authn.x509.ValidationError;
import eu.emi.security.authn.x509.ValidationErrorCode;
import eu.emi.security.authn.x509.ValidationResult;
import eu.emi.security.authn.x509.helpers.CertificateHelpers;
import eu.emi.security.authn.x509.helpers.JavaAndBCStyle;
import eu.emi.security.authn.x509.helpers.ObserversHandler;
import eu.emi.security.authn.x509.helpers.pkipath.bc.FixedBCPKIXCertPathReviewer;
import eu.emi.security.authn.x509.helpers.proxy.ExtendedProxyType;
import eu.emi.security.authn.x509.helpers.proxy.ProxyHelper;
import eu.emi.security.authn.x509.impl.CertificateUtils;
import eu.emi.security.authn.x509.impl.FormatMode;
import eu.emi.security.authn.x509.impl.X500NameUtils;
import eu.emi.security.authn.x509.proxy.ProxyUtils;

/**
 * Low-level certificate validator based on the BC {@link PKIXCertPathReviewer}
 * with additional support for proxy certificates.
 * @author K. Benedyczak
 */
public class BCCertPathValidator
{
	/**
	 * Performs validation. Expects correctly set up parameters.
	 * <p>
	 * If the proxy support is turned off or the chain has no proxy certificate then 
	 * normal X.509 path validation is performed (see below).
	 * <p>
	 * If the proxy support is turned on and the chain has at least one proxy then the 
	 * following checks are performed:
	 * <ul>
	 * <li> The chain is split into two chains A and B, where B ends with the 
	 * first element of A and it is the first not proxy certificate in the original chain
	 * (i.e. the EEC which is the split point).
	 * <li> The chain A is validated using normal X.509 path validation.
	 * <li> The chain B is also validated with the X.509 path validation
	 * but PROXY extension OIDs are recognized, the only trust anchor is the EEC, the
	 * CRLs are ignored, the CA constraint is not required on any issuing certificate 
	 * and the certificate sign bit is also not required.
	 * <li> The chain B is iterated over and on each pair additional checks from the 
	 * RFC 3820 are verified, along with the proxy path limit.
	 * </ul>
	 * <p>
	 * The normal path validation is performed as follows:
	 * <ul>
	 * <li> First all basically correct (i.e. fulfilling name chaining rules) 
	 * certificate paths are tried to be constructed from the input chain. This step
	 * produces from zero to many paths (in 99%: 0 or 1). 
	 * Those paths can differ from the input e.g. by having self-signed intermediary 
	 * CA certificate removed.
	 * <li> If there were no path constructed, the input chain is used as-is, as the only 
	 * possible path. At this step we already know it is invalid, but we anyway continue to
	 * establish complete and detailed list of errors.
	 * <li> All constructed paths are validated using PKIX rules, and errors found are
	 * recorded. If at least one path validates successfully the algorithm ends.
	 * <li> If all paths were invalid, the one with the least number of errors is selected
	 * and those errors are reported as the validation result.
	 * </ul>
	 * 
	 * @param toCheck chain to check
	 * @throws CertificateException if some of the certificates in the chain can not 
	 * be parsed
	 */
	public ValidationResult validate(X509Certificate[] toCheck, boolean proxySupport,
			Set<TrustAnchor> trustAnchors, CertStore crlStore, 
			RevocationParameters revocationParams, ObserversHandler observersHandler)
			throws CertificateException
	{
		if (toCheck == null || toCheck.length == 0)
			throw new IllegalArgumentException("Chain to be validated must be non-empty");

		List<ValidationError> errors = new ArrayList<ValidationError>();
		Set<String> unresolvedExtensions = new HashSet<String>();
		
		
		if (!proxySupport || !ProxyUtils.isProxy(toCheck))
		{
			ExtPKIXParameters params = createPKIXParameters(toCheck, proxySupport, 
					trustAnchors, crlStore, revocationParams, observersHandler);
			List<X509Certificate> chain = checkNonProxyChain(toCheck, params, errors, unresolvedExtensions, 0, toCheck);
			return new ValidationResult(errors.size() == 0, errors, unresolvedExtensions, chain);
		}

		//now we know that we have proxies in the chain and proxy support is turned on
		
		int split = getFirstProxy(toCheck);
		if (split == toCheck.length-1)
		{
			errors.add(new ValidationError(toCheck, -1, ValidationErrorCode.proxyNoIssuer));
			return new ValidationResult(false, errors, unresolvedExtensions, null);
		}
		X509Certificate[] baseChain = new X509Certificate[toCheck.length-split-1];
		X509Certificate[] proxyChain = new X509Certificate[split+2];
		for (int i=split+1; i<toCheck.length; i++)
			baseChain[i-split-1] = toCheck[i];
		for (int i=0; i<split+2; i++)
			proxyChain[i] = toCheck[i];
		
		ExtPKIXParameters params = createPKIXParameters(baseChain, proxySupport, 
				trustAnchors, crlStore, revocationParams, observersHandler);
		List<X509Certificate> validatedChain = checkNonProxyChain(baseChain, params, errors, unresolvedExtensions, split+1, toCheck);
			
		Set<TrustAnchor> trustForProxyChain;
		if (baseChain.length > 1)
			trustForProxyChain = Collections.singleton(
					new TrustAnchor(baseChain[baseChain.length-2], null));
		else
			trustForProxyChain = trustAnchors;
		checkProxyChainWithBC(proxyChain, trustForProxyChain, errors, unresolvedExtensions);
		
		checkProxyChainMain(proxyChain, errors, unresolvedExtensions);
		if (errors.size() == 0 && validatedChain != null)
		{
			for (int j=proxyChain.length-2; j>=0; j--)
				validatedChain.add(0, proxyChain[j]);
		}
		return new ValidationResult(errors.size() == 0, errors, unresolvedExtensions, validatedChain);
	}
	
	protected ExtPKIXParameters createPKIXParameters(X509Certificate[] toCheck, boolean proxySupport,
			Set<TrustAnchor> trustAnchors, CertStore crlStore, 
			RevocationParameters revocationParams, ObserversHandler observersHandler)
	{
		ExtPKIXParameters params;
		X509CertStoreSelector endSelector = new X509CertStoreSelector();
		endSelector.setCertificate(toCheck[0]);
		try
		{
			params = new ExtPKIXParameters(trustAnchors, endSelector, observersHandler);
		} catch (InvalidAlgorithmParameterException e)
		{
			throw new RuntimeException("BUG, never should happen", e);
		}
		params.addCertStore(crlStore);
		
		CertStore certStore;
		try
		{
			certStore = CertStore.getInstance("Collection",
					new CollectionCertStoreParameters(Arrays.asList(toCheck)), 
					BouncyCastleProvider.PROVIDER_NAME);
		} catch (Exception e1)
		{
			throw new RuntimeException("Can't create an instance of a " +
					"simple Collection certificate store, using the BC provider, BUG?", e1);
		}
		params.addCertStore(certStore);
		params.setRevocationParams(revocationParams);
		params.setProxySupport(proxySupport);
		return params;
	}
	
	protected int getFirstProxy(X509Certificate[] toCheck)
	{
		int j;
		for (j=toCheck.length-1; j>=0; j--)
			if (ProxyUtils.isProxy(toCheck[j]))
				return j;
		//can't happen as we call this method with at least one proxy
		throw new RuntimeException("No proxy found, while it should be in chain?? BUG");
	}

	/*
	 * Performs checking of the chain which has no proxies (or at least should not have proxies),
	 * using JCA CertPathBuilder, from BC provider. This is not used in production, 
	 * rather is an alternative implementation useful in testing and debugging.  
	 * @param baseChain
	 * @param params
	 * @param errors
	 * @param unresolvedExtensions
	 * @throws CertificateException
	 */
	/*
	protected void checkNonProxyChain2(X509Certificate[] baseChain, 
			ExtendedPKIXBuilderParameters params, List<ValidationError> errors, 
			Set<String> unresolvedExtensions, int posDelta, X509Certificate[] cc) throws CertificateException
	{
		CertPathBuilder builder;
		try
		{
			builder = CertPathBuilder.getInstance("PKIX", BouncyCastleProvider.PROVIDER_NAME);
		} catch (Exception e1)
		{
			throw new RuntimeException("Can't instantiate PKIX CertPathBuilder " +
					"using the BC provider, really shouldn't happen", e1);
		} 
				
		try
		{
			CertPathBuilderResult res = builder.build(params);
			res.getCertPath();
		} catch (CertPathBuilderException e)
		{
			e.printStackTrace();
			Throwable cause = e.getCause();
			if (cause != null && cause instanceof ExtCertPathValidatorException) {
				errors.add(new ValidationError(cc, -1, ValidationErrorCode.unknownMsg, cause.toString()));
			} else
				errors.add(new ValidationError(cc, -1, ValidationErrorCode.unknownMsg, e.toString()));
		} catch (InvalidAlgorithmParameterException e)
		{
			throw new RuntimeException("BUG, shouldn't happen, parameters " +
					"for the BC CertPathBuilder were prepared correctly.", e);
		}
	}
	*/
	
	/**
	 * Performs checking of the chain which has no proxies (or at least should not have proxies),
	 * using {@link FixedBCPKIXCertPathReviewer}. In future, when BC implementation is fixed
	 * it should use {@link PKIXCertPathReviewer} instead.  
	 * @param baseChain
	 * @param params
	 * @param errors
	 * @param unresolvedExtensions
	 * @return validated chain or null
	 * @throws CertificateException
	 */
	protected List<X509Certificate> checkNonProxyChain(X509Certificate[] baseChain, 
			ExtPKIXParameters params, List<ValidationError> errors, 
			Set<String> unresolvedExtensions, int posDelta, X509Certificate[] cc) 
					throws CertificateException
	{
		NonValidatingCertPathBuilder builder = new NonValidatingCertPathBuilder();
		List<CertPath> certPaths;
		List<ValidationError> buildPathErrors = null;
		try
		{
			certPaths = builder.buildPath(params, baseChain[0], cc);
		} catch (ValidationErrorException e1)
		{
			buildPathErrors = e1.getErrors();
			certPaths = Collections.singletonList(CertificateHelpers.toCertPath(baseChain));
		}
		
		FixedBCPKIXCertPathReviewer baseReviewer;
		List<ValidationError> validationErrors = null;
		List<?>[] rawErrors = null;

		for (int i=0; i<certPaths.size(); i++)
		{
			try
			{
				baseReviewer = new FixedBCPKIXCertPathReviewer(certPaths.get(i), params);
			} catch (CertPathReviewerException e)
			{
				//really shoudn't happen - we have checked the arguments
				throw new RuntimeException("Can't init PKIXCertPathReviewer, bug?", e);
			}
			if (buildPathErrors != null && baseReviewer.isValidCertPath())
			{
				//ups!!! bad! PKIXCertPAthReviewer validated while the path was not even build
				throw new RuntimeException("PKIXCertPAthReviewer validated while the path was not even " +
					"build correctly. Build path error: " + buildPathErrors.get(0));
			}
			
			List<ValidationError> processedErrors = convertErrors(baseReviewer.getErrors(), false, posDelta, cc);
			if (processedErrors.size() == 0) 
			{
				X509Certificate ta = baseReviewer.getTrustAnchor().getTrustedCert();
				if (ta == null)
					return null;
				List<? extends Certificate> path = certPaths.get(i).getCertificates();
				List<X509Certificate> ret = new ArrayList<X509Certificate>(path.size()+1);
				for (int j=0; j<path.size(); j++)
					ret.add((X509Certificate) path.get(j));
				ret.add(ta);
				return ret;
			}
			if (validationErrors == null || validationErrors.size() > processedErrors.size())
			{
				validationErrors = processedErrors;
				rawErrors = baseReviewer.getErrors();
			}
		}

		if (validationErrors != null)
		{
			//let's report errors from the validation which had a smallest number of them
			errors.addAll(validationErrors);
			if (rawErrors != null)
				unresolvedExtensions.addAll(getUnresolvedExtensionons(rawErrors));
		} else
		{
			throw new RuntimeException("PKIXCertPAthReviewer BUG: validationErrors is null, " +
					"tested chain: " + CertificateUtils.format(baseChain, FormatMode.FULL));
		}
		return null;
	}
	
	/**
	 * Checks chain with proxies, starting with the EEC using X.509 path validation. 
	 * EEC issuer is used as the only trust anchor. CRLs are ignored, proxy extension OIDs 
	 * are marked as handled. The error resulting from the missing CA extension is
	 * ignored.  
	 * @param proxyChain
	 * @param errors
	 * @param unresolvedExtensions
	 * @throws CertificateException
	 */
	protected void checkProxyChainWithBC(X509Certificate[] proxyChain, 
			Set<TrustAnchor> trustAnchor, 
			List<ValidationError> errors, Set<String> unresolvedExtensions) 
			throws CertificateException
	{
		CertPath proxyCertPath = CertificateHelpers.toCertPath(proxyChain);
		PKIXCertPathReviewer proxyReviewer;
		try
		{
			PKIXParameters proxyParams = new PKIXParameters(trustAnchor);
			proxyParams.addCertPathChecker(new PKIXProxyCertificateChecker());
			proxyParams.setRevocationEnabled(false);
			proxyReviewer = new PKIXCertPathReviewer(proxyCertPath, proxyParams);
		} catch (InvalidAlgorithmParameterException e1)
		{
			//really shoudn't happen - we have checked the arguments
			throw new RuntimeException("Can't init PKIXParameters, bug?", e1);
		} catch (CertPathReviewerException e)
		{
			//really shoudn't happen - we have checked the arguments
			throw new RuntimeException("Can't init PKIXCertPathReviewer, bug?", e);
		}
		errors.addAll(convertErrors(proxyReviewer.getErrors(), true, 0, proxyChain));
		unresolvedExtensions.addAll(getUnresolvedExtensionons(proxyReviewer.getErrors()));
	}
	
	/**
	 * Performs a validation loop of the proxy chain checking each pair in chain
	 * for the rules not otherwise verified by the base check. Additionally chain length
	 * restriction is verified.
	 * @param proxyChain
	 * @param errors
	 * @param unresolvedExtensions
	 * @throws CertificateException
	 */
	protected void checkProxyChainMain(X509Certificate[] proxyChain, 
			List<ValidationError> errors, Set<String> unresolvedExtensions)
					throws CertificateException
	{
		int remainingLen = Integer.MAX_VALUE;
		int last = proxyChain.length-1;
		
		for (int i=last; i>0; i--)
		{
			try
			{
				checkPairWithProxy(proxyChain[i], proxyChain[i-1], errors, i-1, proxyChain);
				
				if (i != last && remainingLen != Integer.MIN_VALUE)
				{
					int lenRestriction = ProxyHelper.getProxyPathLimit(proxyChain[i]);
					if (lenRestriction < remainingLen)
						remainingLen = lenRestriction-1;
					else
					{
						if (remainingLen != Integer.MAX_VALUE)
							remainingLen--;
					}

					if (remainingLen < 0)
					{
						remainingLen = Integer.MIN_VALUE;
						errors.add(new ValidationError(proxyChain, i-1, ValidationErrorCode.proxyLength));
					}
				}
					
			} catch (CertPathValidatorException e)
			{
				break;
			} catch (IOException e)
			{
				throw new CertificateException("Can't parse the proxy path limit information", e);
			}
		}
	}
	
	
	/**
	 * Checks if the certificate passed as the 2nd argument is a correct proxy 
	 * certificate including checks w.r.t. chain rules with the certificate passed 
	 * as the 1st argument being its issuing certificate. The checks are:
	 * <ul>
	 * <li> proxyCert is a real proxy cert of any type
	 * <li> issuer may not be a CA (3.1)
	 * <li> issuer must have subject set (3.1)
	 * <li> proxy must have issuer equal to issuerCert subject (3.1)
	 * <li> If the Proxy Issuer certificate has the KeyUsage extension, the
	 * Digital Signature bit MUST be asserted. (3.1)
	 * <li> no issuer alternative name extension (3.2)
	 * <li> proxy subject must be the issuerCert subject with appended one CN component (3.4)
	 * <li> no subject alternative name extension (3.5)
	 * <li> no cA basic constraint (3.7)
	 * <li> proxy certificate type (RFC, draft RFC or legacy) must be the same for both certificates
	 * <li> if the issuerCert is restricted then proxyCert must be restricted too.
	 * </ul>
	 * The numbers in brackets refer to the RFC 3820 sections. THe last two rules were added in the version 1.1.0 of
	 * the library.
	 * <p>
	 * 
	 * @param issuerCert certificate of the issuer
	 * @param proxyCert certificate to be checked
	 * @param errors out arg - list of errors found
	 * @param position position in original chain to be used in error reporting
	 */
	protected void checkPairWithProxy(X509Certificate issuerCert, X509Certificate proxyCert, 
			List<ValidationError> errors, int position, X509Certificate[] proxyChain)
			throws CertPathValidatorException, CertificateParsingException
	{
		if (!ProxyUtils.isProxy(proxyCert))
		{
			errors.add(new ValidationError(proxyChain, position, ValidationErrorCode.proxyEECInChain));
			throw new CertPathValidatorException();
		}
		if (proxyCert.getBasicConstraints() >= 0)
			errors.add(new ValidationError(proxyChain, position, ValidationErrorCode.proxyCASet));
		if (proxyCert.getIssuerAlternativeNames() != null)
			errors.add(new ValidationError(proxyChain, position, ValidationErrorCode.proxyIssuerAltNameSet));
		if (proxyCert.getSubjectAlternativeNames() != null)
			errors.add(new ValidationError(proxyChain, position, ValidationErrorCode.proxySubjectAltNameSet));

		if (issuerCert.getBasicConstraints() >= 0)
			errors.add(new ValidationError(proxyChain, position+1, ValidationErrorCode.proxyIssuedByCa));

		X500Principal issuerDN = issuerCert.getSubjectX500Principal();
		if ("".equals(issuerDN.getName()))
		{
			errors.add(new ValidationError(proxyChain, position+1, ValidationErrorCode.proxyNoIssuerSubject));
			throw new CertPathValidatorException();
		}
		if (!X500NameUtils.rfc3280Equal(issuerDN, proxyCert.getIssuerX500Principal()))
			errors.add(new ValidationError(proxyChain, position, ValidationErrorCode.proxySubjectInconsistent));
		boolean[] keyUsage = issuerCert.getKeyUsage();
		if (keyUsage != null && !keyUsage[0])
			errors.add(new ValidationError(proxyChain, position+1, ValidationErrorCode.proxyIssuerNoDsig));
	
		checkLastCNNameRule(proxyCert.getSubjectX500Principal(), issuerDN, errors, position, proxyChain);
		
		if (position+2 != proxyChain.length) //we won't check it for the first pair as it contains an EEC 
		{
			ExtendedProxyType issuerType = ProxyHelper.getProxyType(issuerCert);
			ExtendedProxyType proxyType = ProxyHelper.getProxyType(proxyCert);
			if (issuerType != proxyType)
				errors.add(new ValidationError(proxyChain, position, ValidationErrorCode.proxyTypeInconsistent));
			
			try
			{
				if (ProxyHelper.isLimited(issuerCert) && !ProxyHelper.isLimited(proxyCert))
					errors.add(new ValidationError(proxyChain, position, ValidationErrorCode.proxyInconsistentlyLimited));
			} catch (IOException e)
			{
				throw new CertificateParsingException("Can't establish whether the proxy is limited", e);
			}
		}
		
	}
	
	protected void checkLastCNNameRule(X500Principal srcP, X500Principal issuerP,
			List<ValidationError> errors, int position, X509Certificate[] proxyChain) throws CertPathValidatorException
	{
		X500Name src = CertificateHelpers.toX500Name(srcP);
		X500Name issuer = CertificateHelpers.toX500Name(issuerP);

		RDN[] srcRDNs = src.getRDNs();
		if (srcRDNs.length < 2)
		{
			errors.add(new ValidationError(proxyChain, position+1, ValidationErrorCode.proxySubjectOneRDN));
			throw new CertPathValidatorException();
		} 
		if (srcRDNs[srcRDNs.length-1].isMultiValued())
		{
			errors.add(new ValidationError(proxyChain, position+1, ValidationErrorCode.proxySubjectMultiLastRDN));
			throw new CertPathValidatorException();
		}
		AttributeTypeAndValue lastAVA = srcRDNs[srcRDNs.length-1].getFirst();
		if (!lastAVA.getType().equals(BCStyle.CN))
		{
			errors.add(new ValidationError(proxyChain, position+1, ValidationErrorCode.proxySubjectLastRDNNotCN));
			throw new CertPathValidatorException();
		}
		RDN[] finalRDNs = Arrays.copyOf(srcRDNs, srcRDNs.length-1);
		
		JavaAndBCStyle style = new JavaAndBCStyle();
		X500Name truncatedName = new X500Name(style, finalRDNs);
		if (!style.areEqual(issuer, truncatedName))
			errors.add(new ValidationError(proxyChain, position+1, ValidationErrorCode.proxySubjectBaseWrong));
	}
	
	
	protected List<ValidationError> convertErrors(List<?>[] bcErrorsA, 
			boolean ignoreProxyErrors, int positionDelta, X509Certificate[] cc)
	{
		List<ValidationError> ret = new ArrayList<ValidationError>();
		for (int i=0; i<bcErrorsA.length; i++)
		{
			List<?> bcErrors = bcErrorsA[i];
			for (Object bcError: bcErrors)
			{
				if (bcError instanceof ErrorBundle)
				{
					ErrorBundle error = (ErrorBundle) bcError;
					if (ignoreProxyErrors)
					{
						String id = error.getId();
						if (id.equals("CertPathReviewer.noBasicConstraints"))
							continue;
						if (id.equals("CertPathReviewer.noCACert"))
							continue;
						if (id.equals("CertPathReviewer.noCertSign"))
							continue;
					}
					ret.add(BCErrorMapper.map(error, i-1+positionDelta, cc));
				} else 
				{
					SimpleValidationErrorException error = (SimpleValidationErrorException) bcError;
					if (ignoreProxyErrors)
					{
						ValidationErrorCode id = error.getCode();
						if (id.equals(ValidationErrorCode.noBasicConstraints))
							continue;
						if (id.equals(ValidationErrorCode.noCACert))
							continue;
						if (id.equals(ValidationErrorCode.noCertSign))
							continue;
					}
					ret.add(new ValidationError(cc, i-1+positionDelta, 
						error.getCode(), error.getArguments()));
				}
					
			}
		}
		return ret;
	}
	
	protected Set<String> getUnresolvedExtensionons(List<?>[] bcErrorsA)
	{
		Set<String> ret = new HashSet<String>();
		for (int i=0; i<bcErrorsA.length; i++)
		{
			List<?> bcErrors = bcErrorsA[i];
			for (Object bcError: bcErrors)
			{
				if (bcError instanceof ErrorBundle)
				{
					ErrorBundle error = (ErrorBundle) bcError;
					if (error.getId().equals("CertPathReviewer.unknownCriticalExt"))
					{
						DERObjectIdentifier extId = (DERObjectIdentifier) error.getArguments()[0];
						ret.add(extId.getId());
					}
				} else
				{
					SimpleValidationErrorException error = (SimpleValidationErrorException) bcError;
					if (error.getCode().equals(ValidationErrorCode.unknownCriticalExt))
					{
						DERObjectIdentifier extId = (DERObjectIdentifier) error.getArguments()[0];
						ret.add(extId.getId());
					}
				}
			}
		}
		return ret;
	}
}
