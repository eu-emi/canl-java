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
 * The objects are matched by the subject name. This implementation is useful for Globus-like 
 * EACL policies.
 * This class it thread safe.
 * 
 * @author K. Benedyczak
 */
public class GlobusNamespacesStore extends AbstractGlobusNamespacesStore
{
	/**
	 * This structure holds the complete namespaces information. The primary map key is the hash
	 * name of the file from which some of the policies were loaded. At the same time it is a hash of the subject
	 * name of the CA for which the namespaces were directly defined.
	 * The internal map is indexed with issuer names, i.e. the names of the CA subjects for which we have policies.
	 * The value is a list with all the policies for the CA, in order of appearance in the policy file.
	 */
	protected Map<String, Map<String, List<NamespacePolicy>>> policiesByName;

	public GlobusNamespacesStore(ObserversHandler observers, boolean openssl1Mode)
	{
		super(observers, openssl1Mode);
		policiesByName = new HashMap<String, Map<String, List<NamespacePolicy>>>(1);
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
		for (NamespacePolicy policy: policies)
			addPolicy(policy, policiesByName);
	}
	
	@Override
	protected List<NamespacePolicy> getPoliciesFor(String definedForHash, String issuerDn)
	{
		Map<String, List<NamespacePolicy>> policiesMap = policiesByName.get(definedForHash);
		if (policiesMap == null)
			return null;
		return policiesMap.get(issuerDn);
	}
}
