/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.impl;


import java.security.InvalidAlgorithmParameterException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;
import java.util.Timer;

import eu.emi.security.authn.x509.NamespaceCheckingMode;
import eu.emi.security.authn.x509.ValidationError;
import eu.emi.security.authn.x509.ValidationResult;
import eu.emi.security.authn.x509.helpers.crl.AbstractCRLStoreSPI;
import eu.emi.security.authn.x509.helpers.crl.LazyOpensslCRLStoreSpi;
import eu.emi.security.authn.x509.helpers.crl.OpensslCRLStoreSpi;
import eu.emi.security.authn.x509.helpers.ns.NamespaceChecker;
import eu.emi.security.authn.x509.helpers.pkipath.AbstractValidator;
import eu.emi.security.authn.x509.helpers.trust.LazyOpensslTrustAnchorStoreImpl;
import eu.emi.security.authn.x509.helpers.trust.OpensslTrustAnchorStore;
import eu.emi.security.authn.x509.helpers.trust.OpensslTrustAnchorStoreImpl;


/**
 * The certificate validator which uses OpenSSL directory as a truststore. The validator can work in two modes:
 * the default <b>lazy</b> mode when the truststore contents is loaded on-demand and in a classic mode,
 * when the whole truststore is loaded to the memory at startup. The latter mode can be useful for server-side
 * as allows to get an information about truststore problems (as expired certificates or invalid files) at startup.
 * Also the performance characteristic is better: validation can be faster and operation time more stable.
 * Unfortunately both advantages are at the cost of a longer initialization time and bigger memory footprint.
 * Therefore the lazy mode is strongly suggested for client tools, where this is a concern.
 * 
 *   
 * @author K. Benedyczak
 */
public class OpensslCertChainValidator extends AbstractValidator
{
	private static final X509Certificate[] EMPTY_CERT_ARRAY = new X509Certificate[0];
	private OpensslTrustAnchorStore trustStore;
	private AbstractCRLStoreSPI crlStore;
	private final NamespaceCheckingMode namespaceMode;
	private String path;
	private final boolean lazyMode;
	protected static final Timer timer=new Timer("caNl validator (openssl) timer", true);

	/**
	 * Constructs a new validator instance. This version is equivalent to the {@link #OpensslCertChainValidator(String, boolean, NamespaceCheckingMode, long, ValidatorParams, boolean)}
	 * with the legacy (pre 1.0) format of the truststore and the lazy mode turned on.
	 *  
	 * @param directory path where trusted certificates are stored.
	 * @param namespaceMode specifies how certificate namespaces should be handled
	 * @param updateInterval specifies in miliseconds how often the directory should be 
	 * checked for updates. The files are reloaded only if their modification timestamp
	 * was changed since last load. Use a &lt;= 0 value to disable automatic updates.
	 * @param params common validator settings (revocation, initial listeners, proxy support, ...) 
	 */
	public OpensslCertChainValidator(String directory, NamespaceCheckingMode namespaceMode, 
			long updateInterval, ValidatorParams params)
	{
		this(directory, false, namespaceMode, updateInterval, params, true);
	}
	
	/**
	 * Constructs a new validator instance. This validator will work in the lazy mode. See 
	 * {@link #OpensslCertChainValidator(String, boolean, NamespaceCheckingMode, long, ValidatorParams, boolean)}
	 * for details. 
	 *  
	 * @param directory path where trusted certificates are stored.
	 * @param openssl1Mode if true then truststore is with hashes in openssl 1+ format. Otherwise
	 * the openssl 0.x format is used. 
	 * @param namespaceMode specifies how certificate namespaces should be handled
	 * @param updateInterval specifies in miliseconds how often the directory should be 
	 * checked for updates. The files are reloaded only if their modification timestamp
	 * was changed since last load. Use a &lt;= 0 value to disable automatic updates.
	 * @param params common validator settings (revocation, initial listeners, proxy support, ...) 
	 */
	public OpensslCertChainValidator(String directory, boolean openssl1Mode, NamespaceCheckingMode namespaceMode, 
			long updateInterval, ValidatorParams params)
	{
		this(directory, openssl1Mode, namespaceMode, updateInterval, params, true);
	}	
	
	/**
	 * Constructs a new validator instance.
	 *  
	 * @since 2.0.0
	 * @param directory path where trusted certificates are stored.
	 * @param openssl1Mode if true then truststore is with hashes in openssl 1+ format. Otherwise
	 * the openssl 0.x format is used. 
	 * @param namespaceMode specifies how certificate namespaces should be handled
	 * @param updateInterval specifies in miliseconds how often the directory should be 
	 * checked for updates. The files are reloaded only if their modification timestamp
	 * was changed since last load. Use a &lt;= 0 value to disable automatic updates.
	 * @param params common validator settings (revocation, initial listeners, proxy support, ...)
	 * @param lazyMode if true then certificates, CRLs and namespace definitions are loaded on-demand
	 *  (with in-memory caching). If false then the whole truststore contents is loaded at startup and kept in memory. 
	 */
	public OpensslCertChainValidator(String directory, boolean openssl1Mode, NamespaceCheckingMode namespaceMode, 
			long updateInterval, ValidatorParams params, boolean lazyMode)
	{
		super(params.getInitialListeners());
		path = directory;
		this.lazyMode = lazyMode;
		this.namespaceMode = namespaceMode;
		trustStore = lazyMode ?  
				new LazyOpensslTrustAnchorStoreImpl(directory, updateInterval, 
						observers, openssl1Mode)
				:
				new OpensslTrustAnchorStoreImpl(directory, timer, updateInterval, 
						namespaceMode.globusEnabled(), namespaceMode.euGridPmaEnabled(), 
						observers, openssl1Mode);
		try
		{
			crlStore = lazyMode ? 
				new LazyOpensslCRLStoreSpi(directory, updateInterval, observers, openssl1Mode)
				:
				new OpensslCRLStoreSpi(directory, updateInterval, timer, observers, openssl1Mode);
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
	 * The legacy, pre openssl 1.0 format of the truststore is used as well as the lazy loading mode.
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
	 * The legacy, pre openssl 1.0 format of the truststore is used as well as the lazy loading mode.
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
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public ValidationResult validate(X509Certificate[] certChain)
	{
		Set<TrustAnchor> anchors;
		if (lazyMode)
		{
			LazyOpensslTrustAnchorStoreImpl lazyTAStore = (LazyOpensslTrustAnchorStoreImpl) trustStore;
			anchors = lazyTAStore.getTrustAnchorsFor(certChain);
		} else
		{
			anchors = trustStore.getTrustAnchors(); 
		}
		ValidationResult result = super.validate(certChain, anchors); 
		
		validateNamespaces(certChain, result);
		return result;
	}

	private void validateNamespaces(X509Certificate[] certChain, ValidationResult result)
	{
		NamespaceChecker checker = new NamespaceChecker(namespaceMode, trustStore.getPmaNsStore(), 
				trustStore.getGlobusNsStore());
		
		X509Certificate[] certChainToValidate = result.isValid() ? result.getValidChain().toArray(EMPTY_CERT_ARRAY) : certChain;
		List<ValidationError> errors = checker.check(certChainToValidate);
		processErrorList(errors);
		result.addErrors(errors);
	}
}





