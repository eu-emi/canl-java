/*
 * Copyright (c) 2011 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.helpers;

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
