/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.proxy;

/**
 * Specifies the type of the proxy chain.
 * 
 * @author K. Benedyczak
 */
public enum ProxyChainType
{
	/**
	 * A chain contains only legacy Globus 2 proxies.
	 */
	LEGACY, 
	
	/**
	 * A chain contains only draft RFC proxies.
	 */
	DRAFT_RFC, 
	
	/**
	 * A chain contains only RFC 3820 conformant proxies.
	 */
	RFC3820,
	
	/**
	 * A chain contains proxies of different types (legacy, draft RFC or RFC).
	 */
	MIXED;
	
	/**
	 * Converts this chain type to {@link ProxyType}. Works only if the 
	 * chain is consistent, i.e. if all proxies are of the same type.
	 * @return the chain type as the {@link ProxyType} 
	 * @throws IllegalStateException if this enum value is MIXED
	 */
	public ProxyType toProxyType() throws IllegalStateException
	{
		if (equals(DRAFT_RFC))
			return ProxyType.DRAFT_RFC;
		if (equals(RFC3820))
			return ProxyType.RFC3820;
		if (equals(LEGACY))
			return ProxyType.LEGACY;
		throw new IllegalStateException("Can't convert MIXED ProxyChainType to ProxyType");
	}
}
