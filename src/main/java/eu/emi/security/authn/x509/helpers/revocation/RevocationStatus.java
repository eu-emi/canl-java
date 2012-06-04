/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.revocation;

/**
 * Covers possible generic revocation checking outcomes, in case when certificate being checked <b>is not revoked</b>.
 * For reporting revoked state an appropriate exception is thrown, possibly with additional data about 
 * revocation reason etc.
 *  
 * @author K. Benedyczak
 */
public enum RevocationStatus
{
	/**
	 * Revocation check was performed and it confirmed that the checked certificate is fine.
	 */
	verified,
	
	/**
	 * Revocation check finished without any errors, but it was not possible to make a decision. 
	 * E.g. the OCSP responder returned 'unknown' status or there was no CRL for the CA of
	 * the certificate being checked.  
	 */
	unknown
}
