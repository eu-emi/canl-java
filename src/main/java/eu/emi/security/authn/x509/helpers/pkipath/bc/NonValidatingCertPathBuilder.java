package eu.emi.security.authn.x509.helpers.pkipath.bc;

import java.security.cert.CertPath;
import java.security.cert.CertPathBuilderSpi;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.jce.provider.AnnotatedException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.PKIXCertPathBuilderSpi;
import org.bouncycastle.x509.ExtendedPKIXBuilderParameters;

import eu.emi.security.authn.x509.ValidationError;
import eu.emi.security.authn.x509.ValidationErrorCode;
import eu.emi.security.authn.x509.impl.CertificateUtils;
import eu.emi.security.authn.x509.impl.FormatMode;

/**
 * This class is a modified copy of BC's {@link PKIXCertPathBuilderSpi}. The
 * difference is that this class is building the path only, it is not further
 * validating it. Additionally this class report errors as exceptions with 
 * {@link ValidationError} inside.
 * 
 * @see CertPathBuilderSpi
 * @see PKIXCertPathBuilderSpi
 */
public class NonValidatingCertPathBuilder
{
	/**
	 * Build and validate a CertPath using the given parameter.
	 * 
	 * @param pkixParams PKIXBuilderParameters object containing certificates
	 * to build the CertPath
	 * @param target Target certificate for the path
	 * @throws ValidationErrorException 
	 */
	public CertPath buildPath(ExtendedPKIXBuilderParameters pkixParams, 
			X509Certificate target, X509Certificate[] origChain) throws ValidationErrorException
	{
		List<X509Certificate> certPathList = new ArrayList<X509Certificate>();
		CertPath result = build(target, pkixParams, certPathList, origChain);

		if (result == null && certPathException != null)
			throw certPathException;

		return result;
	}

	private ValidationErrorException certPathException;

	protected CertPath build(X509Certificate tbvCert, ExtendedPKIXBuilderParameters pkixParams,
			List<X509Certificate> tbvPath, final X509Certificate[] origChain)
	{
		// If tbvCert is readily present in tbvPath, it indicates having
		// run
		// into a cycle in the
		// PKI graph.
		if (tbvPath.contains(tbvCert))
		{
			return null;
		}
		// step out, the certificate is not allowed to appear in a
		// certification
		// chain.
		if (pkixParams.getExcludedCerts().contains(tbvCert))
		{
			return null;
		}
		// test if certificate path exceeds maximum length
		if (pkixParams.getMaxPathLength() != -1)
		{
			if (tbvPath.size() - 1 > pkixParams.getMaxPathLength())
			{
				return null;
			}
		}

		tbvPath.add(tbvCert);

		CertificateFactory cFact;
		CertPath builderResult = null;

		try
		{
			cFact = CertificateFactory.getInstance("X.509",	BouncyCastleProvider.PROVIDER_NAME);
		} catch (Exception e)
		{
			// cannot happen
			throw new RuntimeException("Exception creating support classes.");
		}

		try
		{
			// check whether the issuer of <tbvCert> is a TrustAnchor
			TrustAnchor ta;
			try
			{
				ta = CertPathValidatorUtilities.findTrustAnchor(tbvCert,
						pkixParams.getTrustAnchors(), pkixParams.getSigProvider());
			} catch (AnnotatedException e1)
			{
				throw new ValidationErrorException(new ValidationError(origChain, -1, 
						ValidationErrorCode.noTrustAnchorFound));
			}
			
			
			if (ta != null)
			{
				// exception message from possibly later tried certification chains
				try
				{
					return cFact.generateCertPath(tbvPath);
				} catch (Exception e)
				{
					throw new ValidationErrorException(new ValidationError(origChain, -1, 
							ValidationErrorCode.unknownMsg, 
							"Certification path could not be constructed from certificate list: "
							+	e));
				}
			} else
			{
				// add additional X.509 stores from locations in
				// certificate
				try
				{
					CertPathValidatorUtilities.addAdditionalStoresFromAltNames(
							tbvCert, pkixParams);
				} catch (CertificateParsingException e)
				{
					throw new ValidationErrorException(new ValidationError(origChain, -1, 
							ValidationErrorCode.inputError, 
							"No additiontal X.509 stores can be added from certificate locations as " +
							"issuer alternative name extension can not be parsed: " + e.toString()));
				}
				Collection<Object> issuers = new HashSet<Object>();
				// try to get the issuer certificate from one
				// of the stores
				try
				{
					issuers.addAll(CertPathValidatorUtilities.findIssuerCerts(
							tbvCert, pkixParams));
				} catch (org.bouncycastle.jce.provider.AnnotatedException e)
				{
					throw new ValidationErrorException(new ValidationError(origChain, -1, 
							ValidationErrorCode.unknownMsg, 
							"Low level error occured: Cannot find issuer certificate " +
							"for certificate in certification path: " + e));
				}
				if (issuers.isEmpty())
				{
					throw new ValidationErrorException(new ValidationError(origChain, -1, 
							ValidationErrorCode.invalidCertificatePath, 
							CertificateUtils.format(tbvCert, FormatMode.COMPACT_ONE_LINE)));
				}
				Iterator<?> it = issuers.iterator();

				while (it.hasNext() && builderResult == null)
				{
					X509Certificate issuer = (X509Certificate) it.next();
					builderResult = build(issuer, pkixParams, tbvPath, origChain);
				}
			}
		} catch (ValidationErrorException e)
		{
			if (certPathException == null)
				certPathException = new ValidationErrorException();
			certPathException.addErrors(e.getErrors());
		}
		if (builderResult == null)
		{
			tbvPath.remove(tbvCert);
		}
		return builderResult;
	}
}
