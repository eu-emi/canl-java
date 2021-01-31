/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.impl;

import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import eu.emi.security.authn.x509.X509CertChainValidator;
import eu.emi.security.authn.x509.X509Credential;
import eu.emi.security.authn.x509.helpers.ssl.HostnameToCertificateChecker;
import eu.emi.security.authn.x509.helpers.ssl.SSLTrustManager;

/**
 * Simple utility allowing programmers to quickly create SSL socket factories
 * using {@link X509CertChainValidator}.
 * 
 * @author K. Benedyczak
 * @deprecated Use {@link SocketFactoryCreator2} instead, which handles hostname verification in a safer way.
 * Hostname verification provided in this class requires manual wiring and in certain server configuration may cause connection errors.
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
	 * @param c credential to use for the created sockets. If null, then anonymous socket will be created, 
	 * what is useful only for client side.
	 * @param v validator to use for certificates validation
	 * @param r implementation providing random numbers
	 * @return initialized {@link SSLContext} object
	 */
	public static SSLContext getSSLContext(X509Credential c, 
			X509CertChainValidator v, SecureRandom r)
	{
		KeyManager[] kms = c == null ? null : new KeyManager[] {c.getKeyManager()};
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
			sslCtx.init(kms, new TrustManager[] {tm}, r);
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
	 * @param c credential to use for the server socket
	 * @param v validator to use for client's validation
	 * @return configured {@link SSLServerSocketFactory}
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
	 * @param c credential to use for the client socket
	 * @param v validator to use for server's validation
	 * @return configured {@link SSLSocketFactory}
	 */
	public static SSLSocketFactory getSocketFactory(X509Credential c, X509CertChainValidator v)
	{
		return getSocketFactory(c, v, new SecureRandom());
	}
	
	
	/**
	 * This method, invoked on an initialized SSL socket will perform the initial handshake (if necessary)
	 * and then check if the peer's hostname is matching its certificate. The reaction to a mismatch 
	 * must be handled by the provided callback. 
	 *  
	 * @param socket socket to be checked
	 * @param callback used when there is mismatch.
	 * @throws SSLPeerUnverifiedException if the peer was not verified 
	 */
	public static void connectWithHostnameChecking(SSLSocket socket, HostnameMismatchCallback callback) 
			throws SSLPeerUnverifiedException
	{
		HostnameToCertificateChecker checker = new HostnameToCertificateChecker();
		SSLSession session = socket.getSession();
		
		X509Certificate cert;
		Certificate[] serverChain = session.getPeerCertificates();
		if (serverChain == null || serverChain.length == 0)
			throw new IllegalStateException("JDK BUG? Got null or empty peer certificate array");
		if (!(serverChain[0] instanceof X509Certificate))
			throw new ClassCastException("Peer certificate should be " +
					"an X.509 certificate, but is " + serverChain[0].getClass().getName());
		cert = (X509Certificate) serverChain[0];

		String hostname = socket.getInetAddress().getHostName();
		
		try
		{
			if (!checker.checkMatching(hostname, cert))
				callback.nameMismatch(socket, cert, hostname);
		} catch (Exception e)
		{
			throw new IllegalStateException("Can't check peer's address against its certificate", e);
		}
	}
}


