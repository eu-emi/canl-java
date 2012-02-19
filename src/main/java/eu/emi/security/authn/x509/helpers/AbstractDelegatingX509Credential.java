/*
 * Copyright (c) 2011 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.helpers;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.net.ssl.X509ExtendedKeyManager;

import eu.emi.security.authn.x509.X509Credential;

/**
 * Abstract base for credential implementations which delegate to
 * another one.
 *  
 * @author K. Benedyczak
 */
public abstract class AbstractDelegatingX509Credential implements X509Credential
{
	protected X509Credential delegate;
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public KeyStore getKeyStore()
	{
		return delegate.getKeyStore();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public X509ExtendedKeyManager getKeyManager()
	{
		return delegate.getKeyManager();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public char[] getKeyPassword()
	{
		return delegate.getKeyPassword();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String getKeyAlias()
	{
		return delegate.getKeyAlias();
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public PrivateKey getKey()
	{
		return delegate.getKey();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public X509Certificate getCertificate()
	{
		return delegate.getCertificate();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public X509Certificate[] getCertificateChain()
	{
		return delegate.getCertificateChain();
	}
}
