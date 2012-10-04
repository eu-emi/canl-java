/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.impl;


import java.security.InvalidAlgorithmParameterException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Timer;

import eu.emi.security.authn.x509.NamespaceCheckingMode;
import eu.emi.security.authn.x509.ValidationError;
import eu.emi.security.authn.x509.ValidationResult;
import eu.emi.security.authn.x509.helpers.crl.OpensslCRLStoreSpi;
import eu.emi.security.authn.x509.helpers.ns.NamespaceChecker;
import eu.emi.security.authn.x509.helpers.pkipath.AbstractValidator;
import eu.emi.security.authn.x509.helpers.trust.OpensslTrustAnchorStore;


/**
 * The certificate validator which uses OpenSSL directory as a truststore. 
 * @author K. Benedyczak
 */
public class OpensslCertChainValidator extends AbstractValidator
{
	private OpensslTrustAnchorStore trustStore;
	private OpensslCRLStoreSpi crlStore;
	private NamespaceCheckingMode namespaceMode;
	private String path;
	private Timer timer;
	
	/**
	 * Constructs a new validator instance.
	 *  
	 * @param directory path where trusted certificates are stored.
	 * @param namespaceMode specifies how certificate namespaces should be handled
	 * @param updateInterval specifies in miliseconds how often the directory should be 
	 * checked for updates. The files are reloaded only if their modification timestamp
	 * was changed since last load. Use a <= 0 value to disable automatic updates.
	 * @param params common validator settings (revocation, initial listeners, proxy support, ...) 
	 */
	public OpensslCertChainValidator(String directory, NamespaceCheckingMode namespaceMode, 
			long updateInterval, ValidatorParams params)
	{
		super(params.getInitialListeners());
		path = directory;
		this.namespaceMode = namespaceMode;
		timer = new Timer("caNl validator (openssl) timer", true);
		trustStore = new OpensslTrustAnchorStore(directory, timer, updateInterval, 
				namespaceMode.globusEnabled(), namespaceMode.euGridPmaEnabled(), 
				observers);
		try
		{
			crlStore = new OpensslCRLStoreSpi(directory, updateInterval, timer, observers);
		} catch (InvalidAlgorithmParameterException e)
		{
			throw new RuntimeException("BUG: OpensslCRLStoreSpi " +
					"can not be initialized", e);
		}
		init(trustStore, crlStore, params.isAllowProxy(), params.getRevocationSettings());
	}
	
	/**
	 * Constructs a new validator instance with default additional settings
	 * (see {@link ValidatorParams#ValidatorParams()}).
	 *  
	 * @param directory path where trusted certificates are stored.
	 * @param namespaceMode specifies how certificate namespaces should be handled
	 * @param updateInterval specifies in miliseconds how often the directory should be 
	 * checked for updates. The files are reloaded only if their modification timestamp
	 * was changed since last load.
	 */
	public OpensslCertChainValidator(String directory, NamespaceCheckingMode namespaceMode, 
			long updateInterval)
	{
		this(directory, namespaceMode, updateInterval, new ValidatorParams());
	}

	/**
	 * Constructs a new validator instance using the default settings:
	 * CRLs are used if present, proxy certificates are supported and
	 * directory is rescanned every 10mins. EuGridPMA namespaces are checked in the first place,
	 * if not found then Globus EACLs are tried. Lack of namespaces is ignored. 
	 *  
	 * @param directory path where trusted certificates are stored.
	 */
	public OpensslCertChainValidator(String directory)
	{
		this(directory, NamespaceCheckingMode.EUGRIDPMA_GLOBUS, 600000, 
			new ValidatorParamsExt());
	}
	
	/**
	 * Returns the trusted certificates directory path
	 * @return the path
	 */
	public String getTruststorePath()
	{
		return path;
	}
	
	/**
	 * Returns the namespace checking mode.
	 * @return the namespace mode
	 */
	public NamespaceCheckingMode getNamespaceCheckingMode()
	{
		return namespaceMode;
	}
	
	/**
	 * Returns the interval between subsequent checks of the trusted certificates
	 * directory. Note that files are actually reread only if their modification
	 * time has changed.
	 * @return the current refresh interval in milliseconds
	 */
	public long getUpdateInterval()
	{
		return trustStore.getUpdateInterval();
	}

	/**
	 * Sets a new interval between subsequent checks of the trusted certificates
	 * directory. Note that files are actually reread only if their modification
	 * time has changed.
	 * @param updateInterval the new interval to be set in milliseconds
	 */
	public void setUpdateInterval(long updateInterval)
	{
		trustStore.setUpdateInterval(updateInterval);
		crlStore.setUpdateInterval(updateInterval);
	}

	@Override
	public void dispose()
	{
		super.dispose();
		trustStore.dispose();
		crlStore.dispose();
		timer.cancel();
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public synchronized ValidationResult validate(X509Certificate[] certChain)
	{
		ValidationResult result = super.validate(certChain);
		
		NamespaceChecker checker = new NamespaceChecker(namespaceMode, trustStore.getPmaNsStore(), 
				trustStore.getGlobusNsStore());
		List<ValidationError> errors = checker.check(certChain);
		processErrorList(errors);
		result.addErrors(errors);

		return result;
	}
}





