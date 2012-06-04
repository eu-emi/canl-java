/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.pkipath;

import eu.emi.security.authn.x509.ValidationErrorCode;

/**
 * Contains one problem code with optional arguments.
 * @author K. Benedyczak
 */
public class SimpleValidationErrorException extends Exception
{
	private static final long serialVersionUID = 1L;
	private ValidationErrorCode code;
	private Object[] arguments;
	
	public SimpleValidationErrorException(ValidationErrorCode code, Object... arguments)
	{
		this.code = code;
		this.arguments = arguments;
	}
	
	public ValidationErrorCode getCode()
	{
		return code;
	}
	public void setCode(ValidationErrorCode code)
	{
		this.code = code;
	}
	public Object[] getArguments()
	{
		return arguments;
	}
	public void setArguments(Object[] arguments)
	{
		this.arguments = arguments;
	}
}
