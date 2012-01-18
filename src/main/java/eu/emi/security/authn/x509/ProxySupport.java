/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509;

/**
 * Defines proxy support mode for validators.
 * 
 * @author K. Benedyczak
 */
public enum ProxySupport
{
	/**
	 * All kinds of proxies are allowed
	 */
	ALLOW,
	
	/**
	 * All kinds of proxies are denied
	 */
	DENY
}
