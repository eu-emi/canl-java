/*
 * Copyright (c) 2011 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.pkipath;

import java.security.cert.X509Certificate;

import org.bouncycastle.i18n.ErrorBundle;
import org.bouncycastle.i18n.LocaleString;
import org.bouncycastle.x509.PKIXCertPathReviewer;

import eu.emi.security.authn.x509.ValidationError;
import eu.emi.security.authn.x509.ValidationErrorCode;

/**
 * Maps {@link PKIXCertPathReviewer} errors to 
 * {@link ValidationError}. In most cases BC's codes and arguments are simply copied
 * but this class performs few updates when needed. 
 * 
 * @author K. Benedyczak
 */
public class BCErrorMapper
{
	private static final String PFX = "CertPathReviewer.";
	
	public static ValidationError map(ErrorBundle error, int pos, X509Certificate[] cc)
	{
		String id = error.getId();
		if (!id.startsWith(PFX))
			return new ValidationError(cc, pos, ValidationErrorCode.unknownMsg, id);
		id = id.substring(PFX.length());
		
		Object[] args = error.getArguments();
		
		if (id.equals("NoIssuerPublicKey"))
		{
			return new ValidationError(cc, pos, ValidationErrorCode.noIssuerPublicKey);
		}
		if (id.equals("signatureNotVerified"))
		{
			return new ValidationError(cc, pos, ValidationErrorCode.signatureNotVerified, args[1]);
		}
		if (id.equals("certRevoked"))
		{
			LocaleString ls = (LocaleString) args[1];
			return new ValidationError(cc, pos, ValidationErrorCode.certRevoked, args[0], ls.getId());
		}
		
		//the common case
		try
		{
			ValidationErrorCode code = ValidationErrorCode.valueOf(ValidationErrorCode.class, id);
			return new ValidationError(cc, pos, code, args);
		} catch (IllegalArgumentException ile)
		{
			//and a fall back
			return new ValidationError(cc, pos, ValidationErrorCode.unknownMsg, id);
		}
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
