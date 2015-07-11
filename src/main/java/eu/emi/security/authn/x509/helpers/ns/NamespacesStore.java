/*
 * Copyright (c) 2011 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.ns;

import java.security.cert.X509Certificate;
import java.util.Collection;
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
	public void setPolicies(Collection<String> locations);
	
	/**
	 * Gets namespace policies applicable for the CA. The CA must be present in the cert chain, 
	 * at the position given. The subsequent chain elements might be used if there is no explicit policy
	 * defined for the CA itself: then it is checked if any of the parent CAs defined policy for this CA.
	 * @param chain chain
	 * @param position position
	 * @return policies
	 */
	public List<NamespacePolicy> getPolicies(X509Certificate[] chain, int position); 

	/**
	 * As {@link #getPolicies(X509Certificate[], int)} but with principals of certificates only
	 * @param chain chain
	 * @param position position
	 * @return policies
	 */
	public List<NamespacePolicy> getPolicies(X500Principal[] chain, int position); 
}
