/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.impl;

import java.util.ArrayList;
import java.util.Collection;

import eu.emi.security.authn.x509.ProxySupport;
import eu.emi.security.authn.x509.RevocationParameters;
import eu.emi.security.authn.x509.StoreUpdateListener;
import eu.emi.security.authn.x509.X509CertChainValidator;

/**
 * Contains parameters common for all {@link X509CertChainValidator} implementations
 * which use {@link RevocationParametersExt}
 * 
 * @author K. Benedyczak
 */
public class ValidatorParamsExt extends ValidatorParams
{
	protected RevocationParametersExt revocationSettings;
	
	/**
	 * Default constructor: proxies are allowed, no initial update listeners,
	 * default revocation settings.
	 */
	public ValidatorParamsExt()
	{
		this(new RevocationParametersExt(), ValidatorParams.DEFAULT_PROXY_SUPPORT, 
			new ArrayList<StoreUpdateListener>());
	}

	/**
	 * Allows for setting all parameters except the list of initial listeners 
	 * @param revocationSettings desired revocation settings
	 * @param allowProxy whether to allow proxies
	 */
	public ValidatorParamsExt(RevocationParametersExt revocationSettings,
			ProxySupport allowProxy)
	{
		this(revocationSettings, allowProxy, new ArrayList<StoreUpdateListener>());
	}
	
	/**
	 * Full version, allows for setting all parameters.
	 * @param revocationSettings desired revocation settings
	 * @param allowProxy whether to allow proxies
	 * @param initialListeners initial trust store update listeners
	 */
	public ValidatorParamsExt(RevocationParametersExt revocationSettings,
			ProxySupport allowProxy,
			Collection<? extends StoreUpdateListener> initialListeners)
	{
		super(revocationSettings, allowProxy, initialListeners);
		setRevocationSettings(revocationSettings);
	}

	/**
	 * @return revocation checking settings
	 */
	@Override
	public RevocationParametersExt getRevocationSettings()
	{
		return revocationSettings;
	}

	/**
	 * @param revocationSettings  revocation checking settings
	 */
	public void setRevocationSettings(RevocationParametersExt revocationSettings)
	{
		this.revocationSettings = revocationSettings;
	}

	/**
	 * Do not use this method - it will always throw an exception. Use the one 
	 * with extended parameters.
	 * @param revocationSettings  revocation checking settings
	 * 
	 */
	@Override
	public void setRevocationSettings(RevocationParameters revocationSettings)
	{
		throw new IllegalArgumentException("This class can be configured " +
				"only using " + RevocationParametersExt.class);
	}
}
