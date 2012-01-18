/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.pkipath;

import java.util.ArrayList;
import java.util.List;

import eu.emi.security.authn.x509.ValidationError;

/**
 * Wraps a list of {@link ValidationError}
 * @author K. Benedyczak
 */
public class ValidationErrorException extends Exception
{
	private static final long serialVersionUID = 1L;
	private List<ValidationError> errors;

	public ValidationErrorException()
	{
		this.errors = new ArrayList<ValidationError>();
	}

	public ValidationErrorException(ValidationError e)
	{
		this();
		errors.add(e);
	}
	
	public String toString()
	{
		return errors.toString();
	}
	
	public List<ValidationError> getErrors()
	{
		return errors;
	}

	public void setError(List<ValidationError> errors)
	{
		this.errors = errors;
	}
	
	public void addError(ValidationError e)
	{
		this.errors.add(e);
	}
	
	public void addErrors(List<ValidationError> errors)
	{
		this.errors.addAll(errors);
	}
}
