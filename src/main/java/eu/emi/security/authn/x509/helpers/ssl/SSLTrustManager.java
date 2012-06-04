/*
 * Copyright (c) 2011 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.ssl;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import eu.emi.security.authn.x509.ValidationResult;
import eu.emi.security.authn.x509.X509CertChainValidator;

/**
 * Implementation of {@link TrustManager} which uses a configured {@link X509CertChainValidator}
 * to validate certificates.
 * 
 * <p>
 * Note that if the client's certificate is not trusted the server will send an alert and close the connection.
 * Unfortunately, TLS is build in such a way, that in the same time, the client might still be busy 
 * with sending the rest of handshake data (the client's certificate is sent first, then other records). 
 * This alone would be no problem but Java SSL implementation, when trustmanager throws an exception, 
 * first closes the input half of the socket and only then sends the alert. 
 * All this is done without waiting for the client to finish sending its portion of handshake data. 
 * This can cause a race condition: client will try to send data on a closed channel
 * of the socket, before it receives an alert about its certificate. The only known solution is to introduce 
 * a sleep before throwing an exception by checkClientTrusted(). But it is hard to provide a good value, and what is
 * more this timeout is obviously slowing the invalid connection dropping, what might be used to perform DoS attacs.
 * Therefore there is no solution implemented.  
 * 
 * @author K. Benedyczak
 */
public class SSLTrustManager implements X509TrustManager
{
	protected X509CertChainValidator validator;
	
	public SSLTrustManager(X509CertChainValidator validator)
	{
		this.validator = validator;
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void checkClientTrusted(X509Certificate[] chain, String authType)
			throws CertificateException
	{
		checkIfTrusted(chain);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void checkServerTrusted(X509Certificate[] chain, String authType)
			throws CertificateException
	{
		checkIfTrusted(chain);
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
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public X509Certificate[] getAcceptedIssuers()
	{
		return validator.getTrustedIssuers();
	}
}
