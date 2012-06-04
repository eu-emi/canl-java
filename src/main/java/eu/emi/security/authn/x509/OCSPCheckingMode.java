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
	 * Require, for each checked certificate, that at least one valid OCSP responder is defined and 
	 * that at least one responder of those defined returns a correct certificate status. 
	 * If all OCSP responders return error or unknown status, the last one received is treated as a 
	 * critical validation error.
	 * Not suggested, unless it is guaranteed that well configured responder(s) is(are) defined 
	 * and can handle all queries without timeouts.
	 */
	REQUIRE,
	
	/**
	 * Use OCSP for each certificate if a responder is available. OCSP 'unknown' status and 
	 * query errors (as timeout) do not cause the validation to fail. 
	 * Also a lack of defined responder doesn't cause the validation to fail.
	 */
	IF_AVAILABLE,
	
	/**
	 * Do not use OCSP.
	 */
	IGNORE
}
