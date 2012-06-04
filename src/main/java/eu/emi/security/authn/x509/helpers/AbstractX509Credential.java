/*
 * Copyright (c) 2011 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.helpers;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.net.ssl.X509ExtendedKeyManager;

import eu.emi.security.authn.x509.X509Credential;
import eu.emi.security.authn.x509.helpers.ssl.CredentialX509KeyManager;
import eu.emi.security.authn.x509.impl.CertificateUtils;

/**
 * Base class with a shared code for {@link X509Credential} implementations.
 *
 * @author K. Benedyczak
 */
public abstract class AbstractX509Credential implements X509Credential
{
	static 
	{
		CertificateUtils.configureSecProvider();
	}

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
		return new CredentialX509KeyManager(this);
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
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public PrivateKey getKey()
	{
		try
		{
			return (PrivateKey) ks.getKey(getKeyAlias(), getKeyPassword());
		} catch (Exception e)
		{
			throw new RuntimeException("Shouldn't happen: can't " +
					"retrieve key from credential's keystore", e);
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public X509Certificate getCertificate()
	{
		try
		{
			return (X509Certificate) ks.getCertificate(getKeyAlias());
		} catch (KeyStoreException e)
		{
			throw new RuntimeException("Shouldn't happen: can't " +
					"retrieve certificate from credential's keystore", e);
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public X509Certificate[] getCertificateChain()
	{
		try
		{
			return CertificateUtils.convertToX509Chain(
				ks.getCertificateChain(getKeyAlias()));
		} catch (KeyStoreException e)
		{
			throw new RuntimeException("Shouldn't happen: can't " +
					"retrieve certificates from credential's keystore", e);
		}
	}
	
	@Override
	public String getSubjectName()
	{
		return getCertificate().getSubjectX500Principal().getName();
	}
}
