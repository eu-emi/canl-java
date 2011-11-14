/*
 * Copyright (c) 2011 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.ns;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.security.auth.x500.X500Principal;

import eu.emi.security.authn.x509.helpers.trust.OpensslTrustAnchorStore;

/**
 * Provides an in-memory store of {@link NamespacePolicy} objects.
 * The objects are matched either by subject name or by its MD5 hash (needed in case of 
 * SELF subject). This implementation is useful for EuGridPMA namespaces definitions. 
 * This class it thread safe.
 * 
 * @author K. Benedyczak
 */
public class EuGridPmaNamespacesStore extends GlobusNamespacesStore
{
	private Map<String, List<NamespacePolicy>> policiesByHash;

	public EuGridPmaNamespacesStore()
	{
		policiesByHash = new HashMap<String, List<NamespacePolicy>>();
	}
	
	@Override
	public synchronized void setPolicies(List<NamespacePolicy> policies) 
	{
		policiesByName = new HashMap<DNString, List<NamespacePolicy>>(20);
		policiesByHash = new HashMap<String, List<NamespacePolicy>>();
		for (NamespacePolicy policy: policies)
		{
			if (policy.getIssuer().contains("="))
			{
				addGlobusPolicy(policy);
			} else
			{
				List<NamespacePolicy> current = policiesByHash.get(policy.getIssuer());
				if (current == null)
				{
					current = new ArrayList<NamespacePolicy>();
					policiesByHash.put(policy.getIssuer(), current);
				}
				current.add(policy);
			}
		}
	}
	
	@Override
	public synchronized List<NamespacePolicy> getPolicies(X500Principal subject) 
	{
		List<NamespacePolicy> policy = new ArrayList<NamespacePolicy>();
		List<NamespacePolicy> p1 = super.getPolicies(subject);
		if (p1 != null)
			policy.addAll(p1);
		String hash = OpensslTrustAnchorStore.getOpenSSLCAHash(subject);
		List<NamespacePolicy> p2 = policiesByHash.get(hash);
		if (p2 != null)
			policy.addAll(p2);
		if (p1 == null && p2 == null)
			return null;
		return policy;
	}
}
