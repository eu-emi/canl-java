/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509;


/**
 * Implementations receive information about updates of certificate or CRL stores.
 * Most often this listener is used to be notified about update errors.
 * 
 * @author K. Benedyczak
 */
public interface StoreUpdateListener
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
		 * object or the certificate is expired).
		 */
		WARNING,
		
		/**
		 * Plain notification about successful update of the store.
		 */
		NOTIFICATION
	};
	
	/**
	 * Informs about an update related to loading of trust related material, like
	 * loading or downloading a CA certificate, CRL or others.
	 * @param location not null location of the updated resource (URL or file path)
	 * @param type not-null type of resource (CA certificate, CRL files etc)
	 * @param level severity of the notification
	 * @param cause an exception thrown by a loading code, typically IOException. Can be null.
	 * If not null, message of the exception should contain problem description.  
	 */
	public void loadingNotification(String location, String type, Severity level, Exception cause);
}
