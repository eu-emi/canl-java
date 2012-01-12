/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509;


/**
 * Invoked when there is an error found during certificate chain validation.
 * The implementation class can react to the error in application-defined way.
 * In some circumstances the implementation may even decide that the error should 
 * be ignored and that the validation should proceed. 
 * 
 * @author K. Benedyczak
 */
public interface ValidationErrorListener
{
	/**
	 * Invoked upon validation error during chain processing. 
	 * Implementation MAY change the validation error description. 
	 * Returned value determines whether the error shall be ignored 
	 * (true) or not (false).
	 * @param error the error details
	 * @return true if the error shall be ignored, false otherwise.
	 */
	boolean onValidationError(ValidationError error);
}
