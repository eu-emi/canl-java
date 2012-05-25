/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509;

/**
 * Defines On-line Certificate Status Protocol usage mode.
 * 
 * @author K. Benedyczak
 */
public enum OCSPCheckingMode
{
	/**
	 * Require, for each checked certificate, that a valid OCSP responder is defined and returns a
	 * correct certificate status. All OCSP errors and unknown statuses are treated as critical validation errors.
	 * Not suggested, unless it is guaranteed that local responder is defined 
	 * and can handle all queries.
	 */
	REQUIRE,
	
	/**
	 * Use OCSP for each certificate if a responder is available. Unknown status and query errors are not critical.
	 */
	IF_AVAILABLE,
	
	/**
	 * Do not use OCSP.
	 */
	IGNORE
}
