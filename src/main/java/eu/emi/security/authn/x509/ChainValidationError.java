/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509;

import java.security.cert.X509Certificate;


/**
 * Holds information about a single validation problem along with a reference 
 * to the certificate chain which caused the error.
 * 
 * @author K. Benedyczak
 * @see ValidationResult
 * @see ValidationErrorListener
 */
public class ChainValidationError extends ValidationError
{
	private X509Certificate[] chain;
	
	public ChainValidationError(X509Certificate[] chain, int position, 
			ValidationErrorCode errorCode)
	{
		this(chain, position, errorCode, new Object[0]);
	}

	public ChainValidationError(X509Certificate[] chain, int position, 
			ValidationErrorCode errorCode, Object[] params)
	{
		super(position, errorCode, params);
		this.chain = chain;
	}

	/**
	 * 
	 * @return the certificate chain which caused the validation error
	 */
	public X509Certificate[] getChain()
	{
		return chain;
	}
}
