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

import eu.emi.security.authn.x509.impl.OpensslNameUtils;

/**
 * Provides an in-memory store of {@link NamespacePolicy} objects.
 * The objects are matched by the subject name. This implementation is useful for Globus-like 
 * EACL policies.
 * This class it thread safe.
 * 
 * @author K. Benedyczak
 */
public class GlobusNamespacesStore implements NamespacesStore
{
	protected Map<String, List<NamespacePolicy>> policiesByName;

	public GlobusNamespacesStore()
	{
		policiesByName = new HashMap<String, List<NamespacePolicy>>(1);
	}
	
	@Override
	public synchronized void setPolicies(List<NamespacePolicy> policies) 
	{
		policiesByName = new HashMap<String, List<NamespacePolicy>>(20);
		for (NamespacePolicy policy: policies)
			addGlobusPolicy(policy);
	}
	
	protected void addGlobusPolicy(NamespacePolicy policy)
	{
		String issuer = policy.getIssuer();
		List<NamespacePolicy> current = policiesByName.get(issuer);
		if (current == null)
		{
			current = new ArrayList<NamespacePolicy>();
			policiesByName.put(issuer, current);
		}
		current.add(policy);
	}
	
	@Override
	public synchronized List<NamespacePolicy> getPolicies(X500Principal subject) 
	{
		String dn = OpensslNameUtils.convertFromRfc2253(subject.getName(), false);
		
		return policiesByName.get(OpensslNameUtils.normalize(dn));
	}
}
