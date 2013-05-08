/*
 * Copyright (c) 2011 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.ns;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.security.auth.x500.X500Principal;

import eu.emi.security.authn.x509.helpers.trust.OpensslTrustAnchorStore;
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
	/**
	 * This structure holds the complete namespaces information. The primary map key is the hash
	 * name of the file from which some of the policies were loaded. At the same time it is a hash of the subject
	 * name of the CA for which the namespaces were directly defined.
	 * The internal map is indexed with issuer names, i.e. the names of the CA subjects for which we have policies.
	 * The value is a list with all the policies for the CA, in order of appearance in the policy file.
	 */
	protected Map<String, Map<String, List<NamespacePolicy>>> policiesByName;
	protected boolean openssl1Mode;

	public GlobusNamespacesStore(boolean openssl1Mode)
	{
		policiesByName = new HashMap<String, Map<String, List<NamespacePolicy>>>(1);
		this.openssl1Mode = openssl1Mode;
	}
	
	@Override
	public synchronized void setPolicies(List<NamespacePolicy> policies) 
	{
		policiesByName = new HashMap<String, Map<String, List<NamespacePolicy>>>(policies.size());
		for (NamespacePolicy policy: policies)
			addPolicy(policy, policiesByName);
	}
	
	protected void addPolicy(NamespacePolicy policy, Map<String, Map<String, List<NamespacePolicy>>> policies)
	{
		String definedFor = policy.getDefinedFor();
		String issuer = policy.getIssuer();
		Map<String, List<NamespacePolicy>> current = policies.get(definedFor);
		if (current == null)
		{
			current = new HashMap<String, List<NamespacePolicy>>();
			policies.put(definedFor, current);
		}
		
		List<NamespacePolicy> currentList = current.get(issuer);
		if (currentList == null)
		{
			currentList = new ArrayList<NamespacePolicy>();
			current.put(issuer, currentList);
		}
		
		currentList.add(policy);
	}
	
	@Override
	public List<NamespacePolicy> getPolicies(X509Certificate[] chain, int position) 
	{
		X500Principal[] issuers = new X500Principal[chain.length];
		for (int i=position; i<chain.length; i++)
			issuers[i] = chain[i].getIssuerX500Principal();
		return getPolicies(issuers, position);
	}
	
	@Override
	public synchronized List<NamespacePolicy> getPolicies(X500Principal[] chain, int position) 
	{
		X500Principal issuerSubject = chain[position];
		String dn = OpensslNameUtils.convertFromRfc2253(issuerSubject.getName(), false);
		String normalizedDn = OpensslNameUtils.normalize(dn);
		
		for (int i=position; i<chain.length; i++)
		{
			X500Principal issuer = chain[i];
			String hash = OpensslTrustAnchorStore.getOpenSSLCAHash(issuer, openssl1Mode);
			
			List<NamespacePolicy> ret = getPoliciesFor(policiesByName, hash, normalizedDn);
			if (ret != null)
				return ret;
		}
		return null;
	}
	
	protected List<NamespacePolicy> getPoliciesFor(Map<String, Map<String, List<NamespacePolicy>>> policies,
			String definedForHash, String issuerDn)
	{
		Map<String, List<NamespacePolicy>> policiesMap = policies.get(definedForHash);
		if (policiesMap == null)
			return null;
		return policiesMap.get(issuerDn);
	}
}
