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
import eu.emi.security.authn.x509.helpers.SSLTrustManager;

/**
 * Simple utility allowing programmers to quickly create SSL socket factories
 * using {@link X509CertChainValidator}.
 * 
 * @author K. Benedyczak
 */
public class SocketFactoryCreator
{
	static 
	{
		CertificateUtils.configureSecProvider();
	}

	/**
	 * Creates a SSL trustmanager which uses the provided validator. 
	 * @param v validator to use for certificates validation
	 * @return ready to use TrustManager
	 */
	public static X509TrustManager getSSLTrustManager(X509CertChainValidator v)
	{
		return new SSLTrustManager(v);
	}
	
	/**
	 * Low level interface. It can be used to get {@link SSLContext} object initialized with the
	 * provided credential and validator.
	 * @param c credential to use for the created sockets
	 * @param v validator to use for certificates validation
	 * @param r implementation providing random numbers
	 * @return initialized {@link SSLContext} object
	 */
	public static SSLContext getSSLContext(X509Credential c, 
			X509CertChainValidator v, SecureRandom r)
	{
		KeyManager km = c.getKeyManager();
		SSLTrustManager tm = new SSLTrustManager(v);
		SSLContext sslCtx;
		try
		{
			sslCtx = SSLContext.getInstance("TLS");
		} catch (NoSuchAlgorithmException e)
		{
			throw new RuntimeException("The TLS protocol is unsupported by the JDK, " +
					"a serious installation problem?", e);
		}
		try
		{
			sslCtx.init(new KeyManager[] {km}, new TrustManager[] {tm}, r);
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
	 * @param c credential to use for the server socket
	 * @param v validator to use for client's validation
	 * @param r implementation providing random numbers
	 * @return configured {@link SSLServerSocketFactory}
	 */
	public static SSLServerSocketFactory getServerSocketFactory(X509Credential c, 
			X509CertChainValidator v, SecureRandom r)
	{
		return getSSLContext(c, v, r).getServerSocketFactory();
	}

	/**
	 * Same as {@link #getServerSocketFactory(X509Credential, X509CertChainValidator, SecureRandom)} 
	 * using {@link SecureRandom} implementation as the last argument. Note that this
	 * method might block if the machine has not enough system entropy. It is not suggested to use
	 * this method for setting up automatic test environments, however it is suitable for production setups.
	 */
	public static SSLServerSocketFactory getServerSocketFactory(X509Credential c, 
			X509CertChainValidator v)
	{
		return getServerSocketFactory(c, v, new SecureRandom());
	}
	
	/**
	 * Returns an {@link SSLSocketFactory} configured to check
	 * servers' certificates with a provided validator. Client socket will use
	 * the provided credentials.
	 * @param c credential to use for the client socket
	 * @param v validator to use for server's validation
	 * @param r implementation providing random numbers
	 * @return configured {@link SSLSocketFactory}
	 */
	public static SSLSocketFactory getSocketFactory(X509Credential c, X509CertChainValidator v, SecureRandom r)
	{
		return getSSLContext(c, v, r).getSocketFactory();
	}
	
	/**
	 * Same as {@link #getSocketFactory(X509Credential, X509CertChainValidator, SecureRandom)} 
	 * using {@link SecureRandom} implementation as the last argument. Note that this
	 * method might block if the machine has not enough system entropy. It is not suggested to use
	 * this method for setting up automatic test environments, however it is suitable for production setups.
	 */
	public static SSLSocketFactory getSocketFactory(X509Credential c, X509CertChainValidator v)
	{
		return getSocketFactory(c, v, new SecureRandom());
	}
}
