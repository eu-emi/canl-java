/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.impl;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;

import eu.emi.security.authn.x509.X509CertChainValidator;
import eu.emi.security.authn.x509.helpers.pkipath.PlainCRLValidator;
import eu.emi.security.authn.x509.helpers.trust.JDKFSTrustAnchorStore;

/**
 * The certificate validator which uses Java {@link KeyStore} as a truststore.
 * <p>
 * The CRLs (Certificate Revocation Lists, if their handling is turned on) can be obtained
 * from two sources: CA certificate extension defining CRL URL and additional list
 * of URLs manually set by the class user. As an additional feature one may 
 * provide a simple paths to a local files, using wildcards. All files matching a 
 * wildcard are used.
 * <p>
 * This class is thread-safe.
 *  
 * @author K. Benedyczak
 * @see X509CertChainValidator
 */
public class KeystoreCertChainValidator extends PlainCRLValidator
{
	private JDKFSTrustAnchorStore store;
	
	/**
	 * Constructs a new validator instance. CRLs (Certificate Revocation Lists) 
	 * are taken from the trusted CAs certificate extension and downloaded, 
	 * unless CRL checking is disabled. Additional CRLs may be provided manually
	 * with the CRLParams argument. Those CRLs will take precedence over
	 * CRLs from CA certificate extension.  
	 * 
	 * @param truststorePath truststore path
	 * @param password truststore password
	 * @param type truststore type (JKS or PKCS12)
	 * @param truststoreUpdateInterval how often (in ms) the truststore file should be 
	 * checked for updates. The file is reloaded only if its modification timestamp
	 * has changed.
	 * @param params common validator settings (revocation, initial listeners, proxy support, ...)
	 * @throws IOException if the truststore can not be read
	 * @throws KeyStoreException if the truststore can not be parsed or 
	 * if password is incorrect. 
	 */
	public KeystoreCertChainValidator(String truststorePath, char[] password, 
			String type, long truststoreUpdateInterval, 
			ValidatorParamsExt params) 
		throws IOException, KeyStoreException
	{
		super(params.getRevocationSettings(), params.getInitialListeners());
		store = new JDKFSTrustAnchorStore(truststorePath, password, type, 
				timer, truststoreUpdateInterval, observers);
		init(store, crlStoreImplRef.get(), params.isAllowProxy(), params.getRevocationSettings());
	}

	/**
	 * Constructs a new validator instance with default additional settings
	 * (see {@link ValidatorParamsExt#ValidatorParamsExt()}).
	 * 
	 * @param truststorePath truststore path
	 * @param password truststore password
	 * @param type truststore type (JKS or PKCS12)
	 * @param truststoreUpdateInterval how often (in ms) the truststore file should be 
	 * checked for updates. The file is reloaded only if its modification timestamp
	 * has changed.
	 * @throws IOException if the truststore can not be read
	 * @throws KeyStoreException if the truststore can not be parsed or 
	 * if password is incorrect. 
	 */
	public KeystoreCertChainValidator(String truststorePath, char[] password, 
			String type, long truststoreUpdateInterval) 
		throws IOException, KeyStoreException
	{
		this(truststorePath, password, type, truststoreUpdateInterval, 
				new ValidatorParamsExt());
	}
	
	/**
	 * Returns the interval between subsequent checks of the truststore file. 
	 * Note that the file is actually reread only if its modification
	 * time has changed.
	 * @return the current refresh interval in milliseconds
	 */
	public long getTruststoreUpdateInterval()
	{
		return store.getUpdateInterval();
	}

	/**
	 * Sets a new interval between subsequent checks of the truststore
	 * file. Note that the file is actually reread only if its modification
	 * time has changed.
	 * @param updateInterval the new interval to be set in milliseconds
	 */
	public void setTruststoreUpdateInterval(long updateInterval)
	{
		store.setUpdateInterval(updateInterval);
	}

	/**
	 * Returns the current truststore path
	 * @return the path
	 */
	public String getTruststorePath()
	{
		return store.getTruststorePath();
	}
}
