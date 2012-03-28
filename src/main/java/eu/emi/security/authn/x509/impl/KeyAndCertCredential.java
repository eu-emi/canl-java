/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.impl;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import eu.emi.security.authn.x509.X509Credential;
import eu.emi.security.authn.x509.helpers.AbstractX509Credential;
import eu.emi.security.authn.x509.helpers.KeyStoreHelper;

/**
 * Wraps a {@link PrivateKey} and {@link X509Certificate} chain as a {@link X509Credential}.
 * <p>
 * This class is especially useful for quick, in-memory creation of {@link KeyStore} when
 * key and certificate are already loaded.
 * 
 * @author K. Benedyczak
 */
public class KeyAndCertCredential extends AbstractX509Credential
{
	/**
	 * Creates a new instance from the provided key and certificates.
	 * @param privateKey private key to be placed in this {@link X509Credential}'s KeyStore
	 * @param certificateChain certificates to be placed in this {@link X509Credential}'s KeyStore. 
	 * those certificates must match the provided privateKey. The user's certificate is assumed
	 * to be the first entry in the chain.
	 * @throws KeyStoreException  if private key is invalid or doesn't match the certificate. 
	 */
	public KeyAndCertCredential(PrivateKey privateKey, X509Certificate[] certificateChain)
		throws KeyStoreException
	{
		try
		{
			ks = KeyStoreHelper.getInstance("JKS");
		} catch (KeyStoreException e)
		{
			throw new RuntimeException("Can't create JKS KeyStore - JDK is misconfgured?", e);
		}
		
		try
		{
			ks.load(null);
		} catch (Exception e)
		{
			throw new RuntimeException("Can't init JKS KeyStore - JDK is misconfgured?", e);
		}
		
		ks.setKeyEntry(KeystoreCredential.ALIAS, privateKey, 
				KeystoreCredential.KEY_PASSWD, certificateChain);
	}
}
