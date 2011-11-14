/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509;

import eu.emi.security.authn.x509.impl.CrlCheckingMode;


/**
 * Extends the main {@link X509CertChainValidator} interface with some additional methods
 * which are commonly provided by the most validator implementations, but are not
 * strictly required for the sole validation.
 * 
 * @author K. Benedyczak
 * @see X509CertChainValidator
 */
public interface X509CertChainValidatorExt extends X509CertChainValidator
{
	/**
	 * Returns whether this validator supports proxy certificates.
	 * @return true if proxy certificates are suporrted, false otherwise
	 */
	public boolean isProxyAllowed();
	
	/**
	 * Gets the current CRL checking mode.
	 * @return the current mode
	 */
	public CrlCheckingMode getCrlCheckingMode();
	
	/**
	 * Disposes resources used by this Validator, like threads. After calling this method
	 * the validator can not be used anymore.
	 */
	public void dispose();
}
