/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509;

/**
 * This enumeration contains codes of errors that can be signaled 
 * during certificate path validation. This classification is provided
 * to allow applications to have fine grained error handling.
 * <p>
 * This codes are used as keys for getting the messages from the 
 * message bundle 'validationErrors' (defined in a properties file). 
 * 
 * @author K. Benedyczak
 */
public enum ValidationErrorCode
{
	unknown,
	unknownMsg,
	
	nsUndefinedAndRequired,
	nsDeny,
	nsNotAccepted,
	
	inputError,
	emptyCertPath,
	invalidCertificatePath,
	
	proxyEECInChain,
	proxyLength,
	proxyNoIssuer,
	proxyCASet,
	proxyIssuerAltNameSet,
	proxySubjectAltNameSet,
	proxyIssuedByCa,
	proxyNoIssuerSubject,
	proxySubjectInconsistent,
	proxyIssuerNoDsig,
	proxySubjectOneRDN,
	proxySubjectMultiLastRDN,
	proxySubjectLastRDNNotCN,
	proxySubjectBaseWrong,
	proxyTypeInconsistent,
	proxyInconsistentlyLimited,
	
	noIssuerPublicKey,
	noBasicConstraints,
	pathLenghtExtended,
	conflictingTrustAnchors,
	noTrustAnchorFound,
	trustButInvalidCert,
	signatureNotVerified,
	certificateNotYetValid,
	certificateExpired,
	noCACert,
	noCertSign,
	unknownCriticalExt,
	certWrongIssuer,
	errorProcesingBC,
	QcStatementExtError,
	certPathCheckerError,
	criticalExtensionError,
	unknownCriticalExts,
	pubKeyError,
	processLengthConstError,
	rootKeyIsValidButNotATrustAnchor,
	trustAnchorIssuerError,
	trustDNInvalid,
	trustKeyUsage,
	trustPubKeyError,

	explicitPolicy,
	invalidPolicyMapping,
	invalidPolicy,
	noValidPolicyTree,
	policyConstExtError,
	policyExtError,
	policyInhibitExtError,
	policyMapExtError,
	policyQualifierError,

	excludedDN,
	excludedEmail,
	excludedIP,
	ncExtError,
	ncSubjectNameError,
	notPermittedDN,
	notPermittedEmail,
	notPermittedIP,
	subjAltNameExtError,
	
	certRevoked,
	noBaseCRL,
	noValidCrlFound,
	noCrlForExpiredCert,
	crlVerifyFailed,
	deltaCrlExtError,
	distrPtExtError,
	crlAuthInfoAccError,
	crlBCExtError,
	crlDistPtExtError,
	crlExtractionError,
	crlIssuerException,
	crlNbrExtError,
	crlNoIssuerPublicKey,
	crlOnlyAttrCert,
	crlOnlyCaCert,
	crlOnlyUserCert,
	crlReasonExtError,
	onlineCRLWrongCA,
	onlineInvalidCRL,
	noCrlInCertstore,
	noCrlSigningPermited,
	loadCrlDistPointError,
	localInvalidCRL,
	crlUnknownCritExt,
	crlNoIssuerForDP,
	crlNoIssuerAndDP,
	crlIDPAndDPMismatch,
	crlDeltaProblem,
	crlAKIExtError,
	
	ocspCertRevoked,
	ocspNoResponder,
	ocspResponderQueryError,
	ocspResponseInvalid,
	ocspOtherError,
}
