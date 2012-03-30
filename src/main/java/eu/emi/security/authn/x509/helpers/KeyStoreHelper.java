/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchProviderException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * {@link KeyStore} class utility helpers
 * @author K. Benedyczak
 */
public class KeyStoreHelper
{
	/**
	 * Creates an instance of KeyStore using our custom logic for choosing a provider:
	 * BC for PKCS12 and default for others. 
	 * @param type keystore type, usually PKCS12 or JKS
	 * @return keystore object instance. It is not loaded/initialized.
	 * @throws KeyStoreException if there is no provider supporting keystore type
	 */
	public static KeyStore getInstance(String type) throws KeyStoreException
	{
		KeyStore ks;
		try
		{
			if (type.equalsIgnoreCase("PKCS12"))
				ks = KeyStore.getInstance(type, BouncyCastleProvider.PROVIDER_NAME);
			else
				ks = KeyStore.getInstance(type);
			return ks;
		} catch (NoSuchProviderException e)
		{
			throw new IllegalStateException("Bouncy Castle provider is not " +
					"available in JDKFSTrustAnchorStore. This is a BUG.", e);
		}
	}
}
