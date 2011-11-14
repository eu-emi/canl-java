/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.proxy;

/**
 * Specifies the type of the proxy.
 * 
 * @author K. Benedyczak
 */
public enum ProxyType
{
	/**
	 * Legacy Globus 2 proxy
	 */
	LEGACY, 
	/**
	 * Draft RFC proxy
	 */
	DRAFT_RFC, 
	/**
	 * RFC 3820 conformant proxy
	 */
	RFC3820
}
