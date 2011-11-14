/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509;


/**
 * Implementations receive information about various errors which can occur during 
 * updates of certificate or CRL stores.
 * 
 * @author K. Benedyczak
 */
public interface UpdateErrorListener
{
	public static final String CA_CERT = "CA Certificate";
	public static final String CRL = "CRL";
	public static final String EACL_NAMESPACE = "EACL namespace (signing_policy)";
	public static final String EUGRIDPMA_NAMESPACE = "EUGridPMA namespace";
	
	public enum Severity {
		/**
		 * Signifies that the problem was critical, i.e. the 
		 * CRL or certificate was not loaded.
		 */
		ERROR, 
		
		/**
		 * Signifies that the problem was not critical, i.e. the 
		 * CRL or certificate was loaded but with some problems
		 * (e.g. only previously cached version was loaded, not the source
		 * object).
		 */
		WARNING};
	
	/**
	 * Informs about an error related to loading of trust related material, like
	 * loading or downloading a CA certificate, CRL or others.
	 * @param location location of the problematic resource (URL or file path)
	 * @param type type of resource (CA certificate, CRL files etc)
	 * @param level severity of the problem
	 * @param cause an exception thrown by a loading code, typically IOException
	 */
	public void loadingProblem(String location, String type, Severity level, Exception cause);
}
