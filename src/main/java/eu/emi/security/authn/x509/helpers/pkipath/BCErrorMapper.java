/*
 * Copyright (c) 2011 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.pkipath;

import org.bouncycastle.i18n.ErrorBundle;
import org.bouncycastle.i18n.LocaleString;
import org.bouncycastle.x509.PKIXCertPathReviewer;

import eu.emi.security.authn.x509.ValidationError;
import eu.emi.security.authn.x509.ValidationErrorCode;

/**
 * Maps {@link PKIXCertPathReviewer} errors to more friendly messages with codes, wrapped as 
 * {@link ValidationError}. Recognizes only the most common validation errors, for other simply the BC's
 * code is returned.
 * 
 * @author K. Benedyczak
 */
public class BCErrorMapper
{
	private static final String PFX = "CertPathReviewer.";
	
	public static ValidationError map(ErrorBundle error, int pos)
	{
		String id = error.getId();
		if (!id.startsWith(PFX))
			return new ValidationError(pos, ValidationErrorCode.unknownMsg, id);
		id = id.substring(PFX.length());
		
		Object[] args = error.getArguments();
		
		if (id.equals("NoIssuerPublicKey"))
		{
			return new ValidationError(pos, ValidationErrorCode.noIssuerPublicKey);
		}
		if (id.equals("noBasicConstraints"))
		{
			return new ValidationError(pos, ValidationErrorCode.noBasicConstraints);
		}
		if (id.equals("pathLenghtExtended"))
		{
			return new ValidationError(pos, ValidationErrorCode.pathLenghtExtended);
		}
		if (id.equals("conflictingTrustAnchors"))
		{
			return new ValidationError(pos, ValidationErrorCode.conflictingTrustAnchors);
		}
		if (id.equals("noTrustAnchorFound"))
		{
			return new ValidationError(pos, ValidationErrorCode.noTrustAnchorFound);
		}
		if (id.equals("trustButInvalidCert"))
		{
			return new ValidationError(pos, ValidationErrorCode.trustButInvalidCert);
		}
		if (id.equals("signatureNotVerified"))
		{
			return new ValidationError(pos, ValidationErrorCode.signatureNotVerified, args[1]);
		}
		if (id.equals("certificateNotYetValid"))
		{
			return new ValidationError(pos, ValidationErrorCode.certificateNotYetValid, args[0]);
		}
		if (id.equals("certificateExpired"))
		{
			return new ValidationError(pos, ValidationErrorCode.certificateExpired, args[0]);
		}
		if (id.equals("noCACert"))
		{
			return new ValidationError(pos, ValidationErrorCode.noCACert);
		}
		if (id.equals("noCertSign"))
		{
			return new ValidationError(pos, ValidationErrorCode.noCertSign);
		}
		if (id.equals("unknownCriticalExt"))
		{
			return new ValidationError(pos, ValidationErrorCode.unknownCriticalExt);
		}
		if (id.equals("certRevoked"))
		{
			LocaleString ls = (LocaleString) args[1];
			return new ValidationError(pos, ValidationErrorCode.certRevoked, args[0], ls.getId());
		}
		if (id.equals("noBaseCRL"))
		{
			return new ValidationError(pos, ValidationErrorCode.noBaseCRL);
		}
		if (id.equals("noValidCrlFound"))
		{
			return new ValidationError(pos, ValidationErrorCode.noValidCrlFound);
		}
		if (id.equals("crlVerifyFailed"))
		{
			return new ValidationError(pos, ValidationErrorCode.crlVerifyFailed);
		}
		if (id.equals("certWrongIssuer"))
		{
			return new ValidationError(pos, ValidationErrorCode.certWrongIssuer, args[0], args[1]);
		}
		
		return new ValidationError(pos, ValidationErrorCode.unknownMsg, id);
	}
}



/*
List of all BC errors

emptyCertPath
ncSubjectNameError     new Object[] {new UntrustedInput(principal)});
notPermittedDN       new Object[] {new UntrustedInput(principal.getName())});
excludedDN        new Object[] {new UntrustedInput(principal.getName())});
subjAltNameExtError
notPermittedEmail               new Object[] {new UntrustedInput(name)});
notPermittedEmailnew Object[] {new UntrustedInput(email)});
excludedEmail                    new Object[] {new UntrustedInput(email)});

notPermittedDN                    new Object[] {new UntrustedInput(altDNName)});
excludedDN                    new Object[] {new UntrustedInput(altDNName)});
notPermittedIP                    new Object[] {IPtoString(ip)});
excludedIP                    new Object[] {IPtoString(ip)});
ncExtError
processLengthConstError
totalPathLength new Object[] {new Integer(totalPathLength)});
certPathValidDate new Object[] {new TrustedInput(validDate), new TrustedInput(new Date())});
unknown
trustDNInvalid new Object[] {new UntrustedInput(trust.getCAName())});
trustPubKeyError
rootKeyIsValidButNotATrustAnchor
signatureNotVerified     new Object[] {ex.getMessage(),ex,ex.getClass().getName()}); 
crlDistPtExtError
crlAuthInfoAccError
crlDistPoint         new Object[] {new UntrustedUrlInput(urlIt.next())});
ocspLocation     new Object[] {new UntrustedUrlInput(urlIt.next())});
certWrongIssuer    new Object[] {workingIssuerName.getName(),
errorProcesingBC
pubKeyError
policyExtError
policyQualifierError
policyQualifierError
noValidPolicyTree
policyMapExtError
invalidPolicyMapping
invalidPolicyMapping
policyExtError
policyQualifierError
policyConstExtError
policyInhibitExtError
policyConstExtError
explicitPolicy
explicitPolicy
invalidPolicy
certPathCheckerError new Object[] {cpve.getMessage(),cpve,cpve.getClass().getName()});
criticalExtensionError         new Object[] {e.getMessage(),e,e.getClass().getName()});
QcEuCompliance
QcSSCD
QcLimitValueAlpha         new Object[] {limit.getCurrency().getAlphabetic(),
QcLimitValueNum         new Object[] {new Integer(limit.getCurrency().getNumeric()),
QcUnknownStatement    new Object[] {stmt.getStatementId(),new UntrustedInput(stmt)});
QcStatementExtError
crlIssuerException
noCrlInCertstore
crlExtractionError
localValidCRL
localInvalidCRL
onlineCRLWrongCA
onlineValidCRL
onlineInvalidCRL
noCrlSigningPermited
crlVerifyFailed
crlNoIssuerPublicKey
crlReasonExtError
revokedAfterValidation    new Object[] {new TrustedInput(crl_entry.getRevocationDate()),ls});
notRevoked
crlUpdateAvailable
distrPtExtError
deltaCrlExtError
crlIssuerException
crlNbrExtError
crlExtractionError
distrPtExtError
crlBCExtError
crlOnlyUserCert
crlOnlyCaCert
crlOnlyAttrCert
loadCrlDistPointError
trustAnchorIssuerError

*/
