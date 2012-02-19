/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.net.ssl.X509ExtendedKeyManager;

/**
 * Implementations are used to wrap credentials (private key and certificate) 
 * in various formats. Methods allow for converting the wrapped credentials 
 * into the format usable by the Java API.
 *  
 * @author K. Benedyczak
 */
public interface X509Credential
{
	/**
	 * Returns the credential in a keystore.
	 * @return the KeyStore
	 */
	public KeyStore getKeyStore();
	
	/**
	 * Returns a KeyManager which accompanies the KeyStore.  
	 * @return the KeyManager
	 */
	public X509ExtendedKeyManager getKeyManager();
	
	/**
	 * Returns a password which can be used to obtain PrivateKey entry
	 * from the KeyStore returned by the {@link #getKeyStore()} method, 
	 * with the alias returned by the {@link #getKeyAlias()} method.
	 * @return key password
	 */
	public char[] getKeyPassword();
	
	/**
	 * Returns an alias which can be used to obtain the PrivateKey entry
	 * from the KeyStore returned by the {@link #getKeyStore()} method.
	 * @return key alias
	 */
	public String getKeyAlias();
	
	/**
	 * Helper method to get private key from the underlying keystore
	 */
	public PrivateKey getKey();

	/**
	 * Helper method to get certificate from the underlying keystore
	 */
	public X509Certificate getCertificate();

	/**
 	 * Helper method to get certificate chain key from the underlying keystore
	 */
	public X509Certificate[] getCertificateChain();
}
