/*
 * Copyright (c) 2021 Bixbit - Krzysztof Benedyczak. All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.ssl;

import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.X509ExtendedTrustManager;

import eu.emi.security.authn.x509.ValidationResult;
import eu.emi.security.authn.x509.X509CertChainValidator;
import eu.emi.security.authn.x509.impl.HostnameMismatchCallback2;

/**
 * Wires CANL abstractions: credentials and verificators into Java SSL socket factory.
 * Supports hostname verification with a custom callback. If callback is unset then the mismatch of hostname to 
 * peer's certificate is considered a fatal error.
 */
public class SSLTrustManagerWithHostnameChecking extends X509ExtendedTrustManager 
{
	protected final X509CertChainValidator validator;
	private final HostnameToCertificateChecker hostnameChecker = new HostnameToCertificateChecker();
	private final HostnameMismatchCallback2 hostnameMismatchCallback;
	
	public SSLTrustManagerWithHostnameChecking(X509CertChainValidator validator, 
			HostnameMismatchCallback2 hostnameMismatchCallback)
	{
		this.validator = validator;
		this.hostnameMismatchCallback = hostnameMismatchCallback == null ? new DisabledNameMismatchCallback() 
				: hostnameMismatchCallback;
	}
	
	@Override
	public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException 
	{
		checkIfTrusted(chain);
	}

	@Override
	public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException 
	{
		checkIfTrusted(chain);
	}

	@Override
	public X509Certificate[] getAcceptedIssuers() 
	{
		return validator.getTrustedIssuers();
	}

	protected void checkIfTrusted(X509Certificate[] certChain) throws CertificateException
	{
		ValidationResult result = validator.validate(certChain);
		if (!result.isValid())
		{
			result.toString();
			String subject = "";
			if (certChain != null && certChain.length > 0)
				subject = certChain[0].getSubjectX500Principal().getName();
			throw new CertificateException("The peer's certificate with subject's DN " + subject
					+ " was rejected. The peer's certificate status is: " + result.toString());
		}
	}
	
	@Override
	public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket)
			throws CertificateException 
	{
		checkIfTrusted(chain);
		if (socket != null && socket instanceof SSLSocket)
			verifyHostname(chain, (SSLSocket) socket);
	}

	@Override
	public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket)
			throws CertificateException 
	{
		checkIfTrusted(chain);
		if (socket != null && socket instanceof SSLSocket)
			verifyHostname(chain, (SSLSocket) socket);
		
	}

	@Override
	public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
			throws CertificateException 
	{
		checkIfTrusted(chain);
		if (engine != null)
			verifyHostname(chain, engine);
	}

	@Override
	public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
			throws CertificateException 
	{
		checkIfTrusted(chain);
		if (engine != null)
			verifyHostname(chain, engine);
	}

	private void verifyHostname(X509Certificate[] chain, SSLEngine engine) 
			throws CertificateException
	{
		X509Certificate cert = chain[0];
		String hostname = engine.getPeerHost();
		verifyHostname(cert, hostname);
	}

	private void verifyHostname(X509Certificate[] chain, SSLSocket socket) 
			throws CertificateException
	{
		X509Certificate cert = chain[0];
		String hostname = socket.getInetAddress().getHostName();
		verifyHostname(cert, hostname);
	}
	
	private void verifyHostname(X509Certificate cert, String hostname) 
			throws CertificateException
	{
		boolean result;
		try
		{
			result = hostnameChecker.checkMatching(hostname, cert);
		} catch (Exception e)
		{
			throw new IllegalStateException("Can't check peer's address against its certificate", e);
		}
		
		if (!result)
			hostnameMismatchCallback.nameMismatch(cert, hostname);
	}
}
