/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509;

import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.util.MissingResourceException;
import java.util.ResourceBundle;

import eu.emi.security.authn.x509.impl.X500NameUtils;

/**
 * Holds information about a single validation problem with a reference to
 * the certificate chain.
 * Each error may refer to particular certificate in the chain, contains an unique 
 * code and a coarse grained category. 
 * 
 * @author K. Benedyczak
 * @see ValidationResult
 * @see ValidationErrorListener
 * @see ValidationErrorCategory
 */
public class ValidationError
{
	private static final String BUNDLE_NAME = ValidationError.class.getPackage().getName() + 
			"." + "valiadationErrors";
	private int position;
	private ValidationErrorCode errorCode;
	private ValidationErrorCategory errorCategory;
	private String message;
	private Object[] parameters;
	private X509Certificate[] chain;
	
	public ValidationError(X509Certificate[] chain, int position, ValidationErrorCode errorCode, Object... params)
	{
		this.position = position;
		this.chain = chain;
		if (errorCode == null)
			throw new IllegalArgumentException("errorCode can not be null");
		this.errorCode = errorCode;
		this.errorCategory = ValidationErrorCategory.getErrorCategory(errorCode);
		this.parameters = params;
		ResourceBundle bundle = ResourceBundle.getBundle(BUNDLE_NAME);
		String pattern;
		try
		{
			pattern = bundle.getString(errorCode.name());
		} catch (MissingResourceException e)
		{
			pattern = "Other validation error";
		}
		message = MessageFormat.format(pattern, params);
	}
	
	/**
	 * Returns position in chain of the certificate causing the error. 
	 * If the error is related to chain inconsistency (so more then one certificate is
	 * involved) then the lowest number of the certificate 
	 * involved must be returned.
	 * @return position of the erroneous certificate in chain or -1 if not defied. 
	 */
	public int getPosition()
	{
		return position;
	}

	/**
	 * Returns human readable message describing this error. The message is
	 * formatted in accordance to the current locale settings. 
	 * @return the error message
	 */
	public String getMessage()
	{
		return message;
	}

	/**
	 * Gets the unique error code. Error codes are defined in bundle with messages
	 * (in a properties file).   
	 * 
	 * @return the error code
	 */
	public ValidationErrorCode getErrorCode()
	{
		return errorCode;
	}

	/**
	 * Gets the error parameters.
	 * 
	 * @return the error parameters
	 */
	public Object[] getParameters()
	{
		return parameters;
	}

	/**
	 * Returns a coarse grained error category.
	 * @return error category
	 */
	public ValidationErrorCategory getErrorCategory()
	{
		return errorCategory;
	}

	/**
	 * 
	 * @return the certificate chain which caused the validation error
	 */
	public X509Certificate[] getChain()
	{
		return chain;
	}

	public String toString()
	{
		StringBuilder sb = new StringBuilder();
		sb.append("error");
		if (position != -1)
		{
			sb.append(" at position ").append(getPosition()).append(" in chain");
			sb.append(", problematic certificate subject: ").append(
					X500NameUtils.getReadableForm(chain[position].getSubjectX500Principal()));
		} else
			sb.append(" affecting the whole chain");
		sb.append(" (category: ").append(errorCategory).append(")");
		sb.append(": ").append(getMessage());
		return sb.toString();
	}
}
