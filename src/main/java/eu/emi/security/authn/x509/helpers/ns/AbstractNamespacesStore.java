/*
 * Copyright (c) 2011 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.ns;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.security.auth.x500.X500Principal;

import eu.emi.security.authn.x509.StoreUpdateListener.Severity;
import eu.emi.security.authn.x509.helpers.CachedElement;
import eu.emi.security.authn.x509.helpers.ObserversHandler;
import eu.emi.security.authn.x509.helpers.trust.OpensslTruststoreHelper;

/**
 * Policy store common code.
 * <p>  
 * This class it thread safe.
 * 
 * @author K. Benedyczak
 */
public abstract class AbstractNamespacesStore implements NamespacesStore
{
	private static final List<NamespacePolicy> EMPTY = Collections.emptyList();
	
	protected final ObserversHandler observers;
	protected boolean openssl1Mode;

	public AbstractNamespacesStore(ObserversHandler observers, boolean openssl1Mode)
	{
		this.openssl1Mode = openssl1Mode;
		this.observers = observers;
	}
	
	protected abstract String getNotificationType();
	protected abstract NamespacesParser getParser(String path);
	protected abstract String getFileSuffix();
	
	
	protected List<NamespacePolicy> tryLoadNsPath(String path)
	{
		if (path == null)
			return EMPTY;
		NamespacesParser parser = getParser(path);
		try
		{
			List<NamespacePolicy> ret = parser.parse();
			observers.notifyObservers(path, getNotificationType(), Severity.NOTIFICATION, null);
			return ret;
		} catch (FileNotFoundException e) {
			//OK - ignored.
		} catch (IOException e)
		{
			observers.notifyObservers(path, getNotificationType(), Severity.ERROR, e);
		}
		return EMPTY;
	}
	
	protected void tryLoadNsLocation(String location, List<NamespacePolicy> policies)
	{
		String path = OpensslTruststoreHelper.getNsFile(location, getFileSuffix());
		policies.addAll(tryLoadNsPath(path));
	}
	
	
	/**
	 * Adds a given policy to a given map. It is assumed that the map is indexed by issuer hash
	 * and the value maps are indexed by issuer id.
	 * This method is useful only for stores which keep all their namespaces in memory.
	 * @param policy
	 * @param policies
	 */
	protected void addPolicy(NamespacePolicy policy, Map<String, Map<String, List<NamespacePolicy>>> policies)
	{
		String definedFor = policy.getDefinedFor();
		Map<String, List<NamespacePolicy>> current = policies.get(definedFor);
		if (current == null)
		{
			current = new HashMap<String, List<NamespacePolicy>>();
			policies.put(definedFor, current);
		}
		
		addPolicyToMap(policy, current);
	}


	
	/**
	 * Adds policy to a map indexed by a policy issuer.
	 * @param policy
	 * @param map
	 */
	protected void addPolicyToMap(NamespacePolicy policy, Map<String, List<NamespacePolicy>> map)
	{
		String issuer = policy.getIssuer();
		List<NamespacePolicy> currentList = map.get(issuer);
		if (currentList == null)
		{
			currentList = new ArrayList<NamespacePolicy>();
			map.put(issuer, currentList);
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

	/**
	 * Utility method useful for lazy stores. Retrieves a cached policies for the given ca hash and issuer. 
	 * If there is no policy in the cache then it is tried to load one from disk. The 
	 * loaded policy is cached before being returned. 
	 * @param policies
	 * @param definedForHash
	 * @param issuer
	 * @param path
	 * @param maxTTL
	 * @return
	 */
	protected List<NamespacePolicy> getCachedPolicies(Map<String, CachedElement<Map<String, List<NamespacePolicy>>>> policies,
			String definedForHash, String issuer, String path, long maxTTL)
	{
		CachedElement<Map<String, List<NamespacePolicy>>> cachedEntry = policies.get(definedForHash);
		if (cachedEntry != null && !cachedEntry.isExpired(maxTTL))
		{
			Map<String, List<NamespacePolicy>> policiesMap = cachedEntry.getElement();
			return policiesMap.get(issuer);
		}
		List<NamespacePolicy> loaded = tryLoadNsPath(path);
		if (loaded != null)
		{
			Map<String, List<NamespacePolicy>> current = new HashMap<String, List<NamespacePolicy>>();
			for (NamespacePolicy policy: loaded)
				addPolicyToMap(policy, current);
			policies.put(definedForHash, new CachedElement<Map<String,List<NamespacePolicy>>>(current));
		}
		return loaded;
	}
}
