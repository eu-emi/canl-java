/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.trust;

import eu.emi.security.authn.x509.helpers.ns.NamespacesStore;
import eu.emi.security.authn.x509.impl.OpensslCertChainValidator;

/**
 * Implementations of this interface are used by {@link OpensslCertChainValidator} to get access to
 * the trust anchor store. This interface adds possibility to get {@link NamespacesStore}s bound to the trust store.
 * 
 * @author K. Benedyczak
 */
public interface OpensslTrustAnchorStore extends TrustAnchorStore
{
	public static final String CERT_WILDCARD = "????????.*";
	
	public NamespacesStore getPmaNsStore();

	public NamespacesStore getGlobusNsStore();
}


