/*
 * Copyright (c) 2011 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.ns;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import eu.emi.security.authn.x509.helpers.ObserversHandler;

/**
 * Provides an in-memory store of {@link NamespacePolicy} objects.
 * The objects are matched either by subject name or by its MD5 hash (needed in case of 
 * SELF subject). This implementation is useful for EuGridPMA namespaces definitions. 
 * This class it thread safe.
 * 
 * @author K. Benedyczak
 */
public class EuGridPmaNamespacesStore extends AbstractEuGridPmaNamespacesStore
{
	private Map<String, Map<String, List<NamespacePolicy>>> policiesByHash2;
	private Map<String, Map<String, List<NamespacePolicy>>> policiesByName;
	
	public EuGridPmaNamespacesStore(ObserversHandler observers, boolean openssl1Mode)
	{
		super(observers, openssl1Mode);
		policiesByHash2 = new HashMap<String, Map<String, List<NamespacePolicy>>>();
		policiesByName = new HashMap<String, Map<String, List<NamespacePolicy>>>();
	}
	
	@Override
	public void setPolicies(Collection<String> locations)
	{
		List<NamespacePolicy> policies = new ArrayList<NamespacePolicy>();
		for (String location: locations)
			tryLoadNsLocation(location, policies);
		setPolicies(policies);
	}
	
	protected synchronized void setPolicies(List<NamespacePolicy> policies) 
	{
		policiesByName = new HashMap<String, Map<String, List<NamespacePolicy>>>(policies.size());
		policiesByHash2 = new HashMap<String, Map<String, List<NamespacePolicy>>>();
		
		for (NamespacePolicy policy: policies)
		{
			if (policy.getIssuer().contains("="))
			{
				addPolicy(policy, policiesByName);
			} else
			{
				addPolicy(policy, policiesByHash2);
			}
		}
	}

	@Override
	protected List<NamespacePolicy> getPoliciesByIssuerHash(String definedForHash,
			String issuerHash)
	{
		Map<String, List<NamespacePolicy>> policiesMap = policiesByHash2.get(definedForHash);
		if (policiesMap == null)
			return null;
		return policiesMap.get(issuerHash);
	}

	@Override
	protected List<NamespacePolicy> getPoliciesByIssuerDn(String definedForHash, String issuerDn)
	{
		Map<String, List<NamespacePolicy>> policiesMap = policiesByName.get(definedForHash);
		if (policiesMap == null)
			return null;
		return policiesMap.get(issuerDn);
	}

}
