/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.proxy;

public enum ExtendedProxyType
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
	RFC3820,
	/**
	 * not a proxy
	 */
	NOT_A_PROXY
}
