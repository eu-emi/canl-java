/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.proxy;

import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import eu.emi.security.authn.x509.X509Credential;
import eu.emi.security.authn.x509.impl.KeyAndCertCredential;
import eu.emi.security.authn.x509.proxy.ProxyCertificate;

/**
 * Default implementation of the {@link ProxyCertificate} interface.
 * @author K. Benedyczak
 */
public class ProxyCertificateImpl implements ProxyCertificate
{
	private X509Certificate[] chain;
	private PrivateKey privateKey;
	private X509Credential credential;
	
	public ProxyCertificateImpl(X509Certificate[] chain,
			PrivateKey privateKey) throws KeyStoreException
	{
		this.chain = chain;
		this.privateKey = privateKey;
		credential = new KeyAndCertCredential(privateKey, chain);
	}

	public ProxyCertificateImpl(X509Certificate[] chain)
	{
		this.chain = chain;
	}

	@Override
	public X509Certificate[] getCertificateChain()
	{
		return chain;
	}

	@Override
	public PrivateKey getPrivateKey() throws IllegalStateException
	{
		if (privateKey == null)
			throw new IllegalStateException("Private key was not generated for this proxy");
		return privateKey;
	}

	@Override
	public X509Credential getCredential() throws IllegalStateException
	{
		if (privateKey == null)
			throw new IllegalStateException("Private key was not generated for this proxy");
		return credential;
	}

	@Override
	public boolean hasPrivateKey()
	{
		return privateKey != null;
	}
}
