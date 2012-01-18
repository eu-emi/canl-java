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
 * Contains parameters common for all {@link X509CertChainValidator} implementations.
 * 
 * @author K. Benedyczak
 */
public class ValidatorParams
{
	public static final ProxySupport DEFAULT_PROXY_SUPPORT = ProxySupport.ALLOW;
	
	protected ProxySupport allowProxy;
	protected Collection<? extends StoreUpdateListener> initialListeners;
	protected RevocationParameters revocationSettings;
	
	/**
	 * Default constructor: proxies are allowed, no initial update listeners,
	 * default revocation settings.
	 */
	public ValidatorParams()
	{
		this(new RevocationParameters(), ProxySupport.ALLOW, 
			new ArrayList<StoreUpdateListener>());
	}

	/**
	 * Allows for setting all parameters except the list of initial listeners 
	 * @param revocationSettings desired revocation settings
	 * @param allowProxy whether to allow proxies
	 */
	public ValidatorParams(RevocationParameters revocationSettings,
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
	public ValidatorParams(RevocationParameters revocationSettings,
			ProxySupport allowProxy,
			Collection<? extends StoreUpdateListener> initialListeners)
	{
		this.allowProxy = allowProxy;
		this.initialListeners = initialListeners;
		this.revocationSettings = revocationSettings;
	}

	/**
	 * @return whether to allow proxy certificates during validation
	 */
	public ProxySupport isAllowProxy()
	{
		return allowProxy;
	}

	/**
	 * @param allowProxy  whether to allow proxy certificates during validation
	 */
	public void setAllowProxy(ProxySupport allowProxy)
	{
		this.allowProxy = allowProxy;
	}

	/**
	 * @return collection of initial listeners of trust store updates
	 */
	public Collection<? extends StoreUpdateListener> getInitialListeners()
	{
		return initialListeners;
	}

	/**
	 * @param initialListeners  collection of initial listeners of trust store updates
	 */
	public void setInitialListeners(Collection<? extends StoreUpdateListener> initialListeners)
	{
		this.initialListeners = initialListeners;
	}

	/**
	 * @return revocation checking settings
	 */
	public RevocationParameters getRevocationSettings()
	{
		return revocationSettings;
	}

	/**
	 * @param revocationSettings  revocation checking settings
	 */
	public void setRevocationSettings(RevocationParameters revocationSettings)
	{
		this.revocationSettings = revocationSettings;
	}
}
