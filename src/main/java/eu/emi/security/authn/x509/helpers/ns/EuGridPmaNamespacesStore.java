/*
 * Copyright (c) 2011 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.ns;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.security.auth.x500.X500Principal;

import eu.emi.security.authn.x509.StoreUpdateListener;
import eu.emi.security.authn.x509.StoreUpdateListener.Severity;
import eu.emi.security.authn.x509.helpers.ObserversHandler;
import eu.emi.security.authn.x509.helpers.trust.OpensslTruststoreHelper;
import eu.emi.security.authn.x509.impl.OpensslNameUtils;

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
	private Map<String, Map<String, List<NamespacePolicy>>> policiesByHash2;
	
	public EuGridPmaNamespacesStore(ObserversHandler observers, boolean openssl1Mode)
	{
		super(observers, openssl1Mode);
		policiesByHash2 = new HashMap<String, Map<String, List<NamespacePolicy>>>();
	}

	@Override
	protected void tryLoadNs(String location, List<NamespacePolicy> list)
	{
		String path = OpensslTruststoreHelper.getNsFile(location, ".namespaces");
		if (path == null)
			return;
		EuGridPmaNamespacesParser parser = new EuGridPmaNamespacesParser(path, openssl1Mode);
		try
		{
			list.addAll(parser.parse());
			observers.notifyObservers(path, StoreUpdateListener.EUGRIDPMA_NAMESPACE, 
					Severity.NOTIFICATION, null);
		} catch (FileNotFoundException e) {
			//OK - ignored.
		} catch (IOException e)
		{
			observers.notifyObservers(path, StoreUpdateListener.EUGRIDPMA_NAMESPACE, 
					Severity.ERROR, e);
		}
	}
	
	@Override
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
	public synchronized List<NamespacePolicy> getPolicies(X500Principal[] chain, int position) 
	{
		List<NamespacePolicy> policy = new ArrayList<NamespacePolicy>();
		
		X500Principal issuerName = chain[position];
		String issuerDn = OpensslNameUtils.convertFromRfc2253(issuerName.getName(), false);
		String normalizedDn = OpensslNameUtils.normalize(issuerDn);
		String issuerHash = OpensslTruststoreHelper.getOpenSSLCAHash(issuerName, openssl1Mode);

		//iterate over CAs as the policy may be defined for the parent CA.
		for (int i=position; i<chain.length; i++)
		{
			X500Principal casubject = chain[i];
			String definedForHash = OpensslTruststoreHelper.getOpenSSLCAHash(casubject, openssl1Mode);
			
			List<NamespacePolicy> byHash = getPoliciesFor(policiesByHash2, definedForHash, issuerHash);
			List<NamespacePolicy> byName = getPoliciesFor(policiesByName, definedForHash, normalizedDn);
			if (byHash == null && byName == null)
				continue;

			if (byHash != null) {
				policy.addAll(byHash);
				return policy;
			}
			
			if (byName != null) {
				policy.addAll(byName);
				return policy;
			}
		}
		return null;
	}
}
