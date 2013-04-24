/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.proxy;

import java.security.PrivateKey;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;



/**
 * Wraps information about a new proxy certificate signing request which was generated by the {@link ProxyCSRGenerator}.
 * 
 * @author K. Benedyczak
 * @see ProxyCSRGenerator
 */
public interface ProxyCSR
{
	/**
	 * Returns the CSR
	 * 
	 * @return the generated CSR
	 */
	public PKCS10CertificationRequest getCSR();

	/**
	 * Returns the generated private key of this CSR.
	 * 
	 * If public key was manually set an exception is thrown.
	 * 
	 * @return The private key.
	 * @throws IllegalStateException if the private and public keys were not generated
	 */
	public PrivateKey getPrivateKey() throws IllegalStateException;
	
	/**
	 * @return true if private key was generated and is available through 
	 * {@link #getPrivateKey()}
	 */
	public boolean hasPrivateKey();
}
