/*
 * Copyright (c) 2011 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.proxy;

import java.security.PrivateKey;

import org.bouncycastle.jce.PKCS10CertificationRequest;

import eu.emi.security.authn.x509.proxy.ProxyCSR;

/**
 * ProxyCSR implementation.
 * @author K. Benedyczak
 */
public class ProxyCSRImpl implements ProxyCSR
{
	private PKCS10CertificationRequest csr;
	private PrivateKey pk;
	
	/**
	 * @param csr
	 * @param pk use null if PrivateKey was not generated
	 */
	public ProxyCSRImpl(PKCS10CertificationRequest csr, PrivateKey pk)
	{
		this.csr = csr;
		this.pk = pk;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public PKCS10CertificationRequest getCSR()
	{
		return csr;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public PrivateKey getPrivateKey() throws IllegalStateException
	{
		return pk;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean hasPrivateKey()
	{
		return pk == null;
	}

}
