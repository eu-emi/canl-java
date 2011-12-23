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

import eu.emi.security.authn.x509.helpers.DNComparator;
import eu.emi.security.authn.x509.impl.X500NameUtils;

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
	protected Map<DNString, List<NamespacePolicy>> policiesByName;

	public GlobusNamespacesStore()
	{
		policiesByName = new HashMap<DNString, List<NamespacePolicy>>(1);
	}
	
	@Override
	public synchronized void setPolicies(List<NamespacePolicy> policies) 
	{
		policiesByName = new HashMap<DNString, List<NamespacePolicy>>(20);
		for (NamespacePolicy policy: policies)
			addGlobusPolicy(policy);
	}
	
	protected void addGlobusPolicy(NamespacePolicy policy)
	{
		DNString issuer = new DNString(policy.getIssuer());
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
		DNString dn = new DNString(subject.getName());

		return policiesByName.get(dn);
	}
	
	
	/**
	 * String with an RFC 2253 DN wrapper, which uses {@link X500NameUtils} to check for equality.
	 * @author K. Benedyczak
	 */
	protected static class DNString 
	{
		private String dn;

		public DNString(String dn)
		{
			this.dn = dn;
		}

		@Override
		public int hashCode()
		{
			return DNComparator.getHashCode(dn);
		}

		@Override
		public boolean equals(Object obj)
		{
			if (this == obj)
				return true;
			if (obj == null)
				return false;
			if (getClass() != obj.getClass())
				return false;
			DNString other = (DNString) obj;
			if (dn == null)
			{
				if (other.dn != null)
					return false;
			} else if (!X500NameUtils.equal(dn, other.dn))
				return false;
			return true;
		}
	}
}
