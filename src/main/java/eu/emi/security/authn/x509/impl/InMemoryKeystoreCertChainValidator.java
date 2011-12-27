/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.impl;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.util.ArrayList;
import java.util.Collection;

import eu.emi.security.authn.x509.StoreUpdateListener;
import eu.emi.security.authn.x509.X509CertChainValidator;
import eu.emi.security.authn.x509.helpers.pkipath.PlainCRLValidator;
import eu.emi.security.authn.x509.helpers.trust.JDKInMemoryTrustAnchorStore;

/**
 * The certificate validator which uses Java {@link KeyStore} as a truststore. This
 * class is similar to {@link KeystoreCertChainValidator} but uses a keystore which
 * was already loaded. Refreshing of the truststore is not supported. 
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
 * @see KeystoreCertChainValidator
 */
public class InMemoryKeystoreCertChainValidator extends PlainCRLValidator
{
	protected JDKInMemoryTrustAnchorStore store;
	
	/**
	 * Constructs a new validator instance. CRLs (Certificate Revocation Lists) 
	 * are taken from the trusted CAs certificate extension and downloaded, 
	 * unless CRL checking is disabled. Additional CRLs may be provided explicitly
	 * using the constructor argument. Such additional CRLs are preferred to the
	 * ones defined by the CA extensions.
	 * 
	 * @param keystore truststore to use
	 * @param crlParams configuration of CRL sources.
	 * @param crlMode defines overall CRL handling mode
	 * @param allowProxy whether the validator should allow for Proxy certificates
 	 * @param listeners initial list of update listeners. If set in the constructor 
	 * then even the initial problems will be reported (if set via appropriate methods 
	 * then only error of subsequent updates are reported). 
	 * @throws IOException if the truststore can not be read
	 * @throws KeyStoreException if the truststore can not be parsed or 
	 * if password is incorrect. 
	 */
	public InMemoryKeystoreCertChainValidator(KeyStore keystore, 
			CRLParameters crlParams, CrlCheckingMode crlMode, 
			boolean allowProxy, Collection<? extends StoreUpdateListener> listeners) 
		throws IOException, KeyStoreException
	{
		super(crlParams, crlMode, listeners);
		store = new JDKInMemoryTrustAnchorStore(keystore);
		init(store, crlStoreImpl, allowProxy, crlMode);
	}
	
	/**
	 * Constructs a new validator instance. CRLs (Certificate Revocation Lists) 
	 * are taken from the trusted CAs certificate extension and downloaded, 
	 * unless CRL checking is disabled. Additional CRLs may be provided explicitly
	 * using the constructor argument. Such additional CRLs are preferred to the
	 * ones defined by the CA extensions. 
	 * <p>
	 * This constructor doesn't install any initial
	 * CRL update listeners.
	 * 
	 * @param keystore truststore to use
	 * @param crlParams configuration of CRL sources
	 * @param crlMode defines overall CRL handling mode
	 * @param allowProxy whether the validator should allow for Proxy certificates
	 * @throws IOException if the truststore can not be read
	 * @throws KeyStoreException if the truststore can not be parsed or 
	 * if password is incorrect. 
	 */
	public InMemoryKeystoreCertChainValidator(KeyStore keystore, 
			CRLParameters crlParams, CrlCheckingMode crlMode, 
			boolean allowProxy) 
		throws IOException, KeyStoreException
	{
		this(keystore, crlParams, crlMode, allowProxy, 
				new ArrayList<StoreUpdateListener>(0));
	}
	
	
	/**
	 * Returns the current trust store. Note that modifying this keystore
	 * won't have any impact on the validation.
	 * @return the KeyStore used as a trust store
	 */
	public synchronized KeyStore getTruststore()
	{
		return store.getKeyStore();
	}

	/**
	 * Changes the current trust store.
	 * @throws KeyStoreException 
	 */
	public synchronized void setTruststore(KeyStore ks) throws KeyStoreException
	{
		store = new JDKInMemoryTrustAnchorStore(ks);
		init(store, null, isProxyAllowed(), getCrlCheckingMode());
	}
}
