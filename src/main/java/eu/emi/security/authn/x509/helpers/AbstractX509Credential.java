/*
 * Copyright (c) 2011 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.helpers;

import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;

import eu.emi.security.authn.x509.X509Credential;

/**
 * Base class with a shared code for {@link X509Credential} implementations.
 *
 * @author K. Benedyczak
 */
public abstract class AbstractX509Credential implements X509Credential
{
	public static final String ALIAS = "defaultKey";
	public static final char[] KEY_PASSWD = "key!password".toCharArray();
	protected KeyStore ks;

	/**
	 * {@inheritDoc}
	 */
	@Override
	public KeyStore getKeyStore()
	{
		return ks;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public X509ExtendedKeyManager getKeyManager()
	{
		KeyManagerFactory kmFactory;
		try
		{
			kmFactory = KeyManagerFactory.getInstance("SunX509");
		} catch (NoSuchAlgorithmException e)
		{
			throw new RuntimeException("SunX509 algorithm is not known in the JDK" +
					" - JDK is misconfgured?", e);
		}
		try
		{
			kmFactory.init(ks, KEY_PASSWD);
		} catch (Exception e)
		{
			throw new RuntimeException("Can't init key manager factory with " +
					"the correct JKS keystore - a bug?", e);
		}
		KeyManager[] ret = kmFactory.getKeyManagers();
		
		if (ret.length != 1)
			throw new IllegalStateException("Problem in getKeyManager - got more " +
					"then one key manager for a one-key keystore?");
		if (!(ret[0] instanceof X509ExtendedKeyManager))
			throw new IllegalStateException("Problem in getKeyManager - " +
					"got an old KeyManager implementation?");
		return (X509ExtendedKeyManager) ret[0];
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public char[] getKeyPassword()
	{
		return KEY_PASSWD;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String getKeyAlias()
	{
		return ALIAS;
	}
}
