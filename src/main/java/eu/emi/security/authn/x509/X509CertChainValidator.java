/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509;

import java.security.cert.CertPath;
import java.security.cert.X509Certificate;

/**
 * Implementations are used to perform a manual certificate chain validation. 
 * Implementations shall reuse as many of existing CertificateChecker implementations as 
 * possible. Implementations must be thread safe. 
 * 
 * @author K. Benedyczak
 * @see ValidationResult
 */
public interface X509CertChainValidator
{
	/**
	 * Performs validation of a provided certificate path.
	 * @param certPath to be validated
	 * @return result of validation
	 */
	public ValidationResult validate(CertPath certPath);
	
	/**
	 * Performs validation of a provided certificate chain.
	 * @param certChain to be validated
	 * @return result of validation
	 */
	public ValidationResult validate(X509Certificate[] certChain);
	
	/**
	 * Returns a list of trusted issuers of certificates. 
	 * @return array containing trusted issuers' certificates
	 */
	public X509Certificate[] getTrustedIssuers();
	
	/**
	 * Registers a listener which can react to errors found during certificate 
	 * validation. It is useful in two cases: (rarely) if you want to change 
	 * the default logic of the validator and if you will use the validator indirectly
	 * (e.g. to validate SSL socket connections) and want to get the original 
	 * {@link ValidationError}, not the exception. 
	 * 
	 * @param listener to be registered
	 */
	public void addValidationListener(ValidationErrorListener listener);
	
	/**
	 * Unregisters a previously registered validation listener. If the listener
	 * was not registered then the method does nothing. 
	 * @param listener to be unregistered
	 */
	public void removeValidationListener(ValidationErrorListener listener);
	
	
	/**
	 * Registers a listener which can react to errors found during refreshing 
	 * of the trust material: trusted CAs or CRLs. This method is useful only if
	 * the implementation supports updating of CAs or CRLs, otherwise the listener
	 * will not be invoked.  
	 * 
	 * @param listener to be registered
	 */
	public void addUpdateListener(StoreUpdateListener listener);
	
	/**
	 * Unregisters a previously registered CA or CRL update listener. If the listener
	 * was not registered then the method does nothing. 
	 * @param listener to be unregistered
	 */
	public void removeUpdateListener(StoreUpdateListener listener);
}
