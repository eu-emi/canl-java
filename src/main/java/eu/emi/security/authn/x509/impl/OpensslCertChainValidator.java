/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.impl;


import java.security.InvalidAlgorithmParameterException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Timer;

import eu.emi.security.authn.x509.UpdateErrorListener;
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
	 * @param crlMode specifies how CRL should be handled
	 * @param namespaceMode specifies how certificate namespaces should be handled
	 * @param updateInterval specifies in miliseconds how often the directory should be 
	 * checked for updates. The files are reloaded only if their modification timestamp
	 * was changed since last load.
	 * @param allowProxy whether the validator should support proxy certificates.
	 * @param listeners initial list of update listeners. If set in the constructor 
	 * then even the initial problems will be reported (if set via appropriate methods 
	 * then only error of subsequent updates are reported). 
	 */
	public OpensslCertChainValidator(String directory, CrlCheckingMode crlMode, 
			NamespaceCheckingMode namespaceMode, long updateInterval, 
			boolean allowProxy, Collection<? extends UpdateErrorListener> listeners)
	{
		path = directory;
		this.namespaceMode = namespaceMode;
		timer = new Timer();
		trustStore = new OpensslTrustAnchorStore(directory, timer, updateInterval, 
				namespaceMode.globusEnabled(), namespaceMode.euGridPmaEnabled(), listeners);
		try
		{
			crlStore = new OpensslCRLStoreSpi(directory, updateInterval, timer,
					listeners);
		} catch (InvalidAlgorithmParameterException e)
		{
			throw new RuntimeException("BUG: OpensslCRLStoreSpi " +
					"can not be initialized", e);
		}
		
		init(trustStore, crlStore, allowProxy, crlMode);
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
		this(directory, CrlCheckingMode.IF_VALID, 
				NamespaceCheckingMode.EUGRIDPMA_GLOBUS, 600000, true,
				new ArrayList<UpdateErrorListener>(0));
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
		processErrorList(certChain, errors);
		result.addErrors(errors);

		return result;
	}
}





