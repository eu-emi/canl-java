/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.impl;

/**
 * Defines Certificate Revocation List verification mode.
 * 
 * @author K. Benedyczak
 * @see OpensslCertChainValidator
 * @see KeystoreCertChainValidator
 */
public enum CrlCheckingMode
{
	/**
	 * A CRL for CA which issued a certificate being validated 
	 * must be present and valid and the certificate must not be on the list.
	 */
	REQUIRE,
	
	/**
	 * If a CRL for CA which issued a certificate being validated
	 * is present and valid then the certificate must not be listed on the CRL.
	 * If the CRL is present but it is outdated then the validation fails. 
	 * If CRL is missing then validation is successful.
	 */
	IF_VALID,

	/**
	 * CRL is not checked even if it exists.
	 */
	IGNORE
}
