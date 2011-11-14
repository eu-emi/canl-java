/*
 * Copyright (c) 2011 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.ns;

import java.util.List;

import javax.security.auth.x500.X500Principal;


/**
 * Store of {@link NamespacePolicy} objects.
 * The objects are retrieved by the issuer name.
 * The implementations must be thread safe.
 * 
 * @author K. Benedyczak
 */
public interface NamespacesStore
{
	public void setPolicies(List<NamespacePolicy> policies); 
	
	public List<NamespacePolicy> getPolicies(X500Principal subject); 
}
