/*
 * Copyright (c) 2011 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.helpers;

import java.security.cert.CertPath;
import java.security.cert.X509Certificate;

import eu.emi.security.authn.x509.UpdateErrorListener;
import eu.emi.security.authn.x509.ValidationErrorListener;
import eu.emi.security.authn.x509.ValidationResult;
import eu.emi.security.authn.x509.X509CertChainValidator;

/**
 * A simplistic {@link X509CertChainValidator} implementation which always fails or accepts certificates,
 * basing on the constructor argument. Useful for tests and insecure setups (e.g. SSL client that wants
 * SSL encryption but do not use SSL authentication).
 * @author K. Benedyczak
 */
public class BinaryCertChainValidator implements X509CertChainValidator
{
	private boolean acceptAll;
	
	/**
	 * 
	 * @param acceptAll if true then all validations will succeed. If false all will fail.
	 */
	public BinaryCertChainValidator(boolean acceptAll)
	{
		this.acceptAll = acceptAll;
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public ValidationResult validate(CertPath certPath)
	{
		return new ValidationResult(acceptAll);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public ValidationResult validate(X509Certificate[] certChain)
	{
		return new ValidationResult(acceptAll);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public X509Certificate[] getTrustedIssuers()
	{
		return new X509Certificate[0];
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void addValidationListener(ValidationErrorListener listener)
	{
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void removeValidationListener(ValidationErrorListener listener)
	{
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void addUpdateErrorListener(UpdateErrorListener listener)
	{
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void removeUpdateErrorListener(UpdateErrorListener listener)
	{
	}
}
