/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 * 
 * Parts of this class are derived from the glite.security.util-java module, 
 * copyrighted as follows:
 *
 * Copyright (c) Members of the EGEE Collaboration. 2004. See
 * http://www.eu-egee.org/partners/ for details on the copyright holders.
 */
package eu.emi.security.authn.x509.proxy;

import java.security.PublicKey;
import java.security.cert.X509Certificate;

/**
 * Holds parameters which are used to create a proxy certificate using 
 * only a certificate chain.
 * 
 * @see ProxyGenerator
 * @author J. Hahkala
 * @author K. Benedyczak
 */
public class ProxyCertificateOptions extends BaseProxyCertificateOptions
{
	public static final int DEFAULT_KEY_LENGTH = 1024;
	public static final int DEFAULT_LONG_KEY_LENGTH = 2048;
	public static final int LONG_PROXY = 10*24*3600;
	
	private Integer keyLength;
	private PublicKey publicKey = null;
	
	/**
	 * Create a new proxy cert based on the parent cert chain.
	 * Useful when locally creating a proxy from existing cert chain.
	 */
	public ProxyCertificateOptions(X509Certificate[] parentCertChain)
	{
		super(parentCertChain);
	}

	/**
	 * Sets the length of the keys to be generated, only used if the keys
	 * are not set separately. If this method is not used, the default is
	 * 1024 bits.
	 * @param length to be set
	 */
	public void setKeyLength(int length)
	{
		this.keyLength = length;
	}
	
	/**
	 * Gets the length of the keys to be generated. By defualt it returns 
	 * @return the currently set key length
	 */
	public int getKeyLength()
	{
		if (keyLength == null) 
		{
			int lifetime = getLifetime();
			if (lifetime >= LONG_PROXY)
				return DEFAULT_LONG_KEY_LENGTH;
			else
				return DEFAULT_KEY_LENGTH;
		}
		return keyLength;
	}
	
	/**
	 * Manually sets public key which shall be included in the generated proxy
	 * 
	 * @param pubKey the public key to set
	 */
	public void setPublicKey(PublicKey pubKey)
	{
		this.publicKey = pubKey;
	}

	/**
	 * Returns the manually set public key for the proxy.
	 * @return the public key
	 */
	public PublicKey getPublicKey()
	{
		return publicKey;
	}	
}
