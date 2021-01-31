/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.impl;

import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import eu.emi.security.authn.x509.X509CertChainValidator;
import eu.emi.security.authn.x509.X509Credential;
import eu.emi.security.authn.x509.helpers.ssl.SSLTrustManagerWithHostnameChecking;

/**
 * Utility allowing programmers to quickly create SSL socket factories using configuration abstractions
 * of this library. 
 */
public class SocketFactoryCreator2
{
	static 
	{
		CertificateUtils.configureSecProvider();
	}

	
	private final X509Credential credential;
	private final X509CertChainValidator validator;
	private final SecureRandom rnd;
	private final HostnameMismatchCallback2 hostnameMismatchCallback;
	private final String protocol;
	
	public SocketFactoryCreator2(X509Credential credential, X509CertChainValidator validator,
			HostnameMismatchCallback2 hostnameMismatchCallback, SecureRandom rnd, String protocol)
	{
		this.credential = credential;
		this.validator = validator;
		this.rnd = rnd;
		this.hostnameMismatchCallback = hostnameMismatchCallback;
		this.protocol = protocol;
	}

	public SocketFactoryCreator2(X509Credential credential, X509CertChainValidator validator,
			HostnameMismatchCallback2 hostnameMismatchCallback)
	{
		this(credential, validator, hostnameMismatchCallback, new SecureRandom(), "TLS");
	}

	public SocketFactoryCreator2(X509CertChainValidator validator,
			HostnameMismatchCallback2 hostnameMismatchCallback, SecureRandom rnd, String protocol)
	{
		this(null, validator, hostnameMismatchCallback, rnd, protocol);
	}

	public SocketFactoryCreator2(X509CertChainValidator validator,
			HostnameMismatchCallback2 hostnameMismatchCallback)
	{
		this(null, validator, hostnameMismatchCallback, new SecureRandom(), "TLS");
	}
	
	/**
	 * Creates a SSL trustmanager which uses the provided validator. 
	 * @return ready to use TrustManager
	 */
	public X509TrustManager getSSLTrustManager()
	{
		return new SSLTrustManagerWithHostnameChecking(validator, hostnameMismatchCallback);
	}
	
	/**
	 * Low level interface. It can be used to get {@link SSLContext} object initialized with the
	 * provided credential and validator.
	 * @return initialized {@link SSLContext} object
	 */
	public SSLContext getSSLContext()
	{
		KeyManager[] kms = credential == null ? null : new KeyManager[] {credential.getKeyManager()};
		X509TrustManager tm = new SSLTrustManagerWithHostnameChecking(validator, hostnameMismatchCallback);
		SSLContext sslCtx;
		try
		{
			sslCtx = SSLContext.getInstance(protocol);
		} catch (NoSuchAlgorithmException e)
		{
			throw new RuntimeException("The TLS protocol is unsupported by the JDK, " +
					"a serious installation problem?", e);
		}
		try
		{
			sslCtx.init(kms, new TrustManager[] {tm}, rnd);
		} catch (KeyManagementException e)
		{
			throw new RuntimeException("Shouldn't happen - SSLContext can't be initiated?", e);
		}
		return sslCtx;
	}
	
	/**
	 * Returns an {@link SSLServerSocketFactory} configured to check
	 * client certificates with a provided validator. Server socket will use
	 * the provided credentials.
	 * @return configured {@link SSLServerSocketFactory}
	 */
	public SSLServerSocketFactory getServerSocketFactory()
	{
		return getSSLContext().getServerSocketFactory();
	}

	/**
	 * Returns an {@link SSLSocketFactory} configured to check
	 * servers' certificates with a provided validator. Client socket will use
	 * the provided credentials.
	 * @return configured {@link SSLSocketFactory}
	 */
	public SSLSocketFactory getSocketFactory()
	{
		return getSSLContext().getSocketFactory();
	}
}


