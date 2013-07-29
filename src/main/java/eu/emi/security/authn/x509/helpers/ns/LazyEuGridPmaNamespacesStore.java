/*
 * Copyright (c) 2011 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.ns;

import java.io.File;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.WeakHashMap;

import eu.emi.security.authn.x509.helpers.CachedElement;
import eu.emi.security.authn.x509.helpers.ObserversHandler;

/**
 * EuGridPMA namespace policies are loaded on demand by this store and are cached in memory. A
 * weak hash map is used to cache data. Additionally the data is cached for no longer then the 
 * update interval, which in practice is the same as for the cooperating truststore.
 * This class it thread safe.
 * 
 * @author K. Benedyczak
 */
public class LazyEuGridPmaNamespacesStore extends AbstractEuGridPmaNamespacesStore
{
	private Map<String, CachedElement<Map<String, List<NamespacePolicy>>>> policiesByHash;
	private Map<String, CachedElement<Map<String, List<NamespacePolicy>>>> policiesByName;
	protected final String directory;
	protected final long updateInterval;
	
	public LazyEuGridPmaNamespacesStore(ObserversHandler observers, boolean openssl1Mode, String directory,
			long updateInterval)
	{
		super(observers, openssl1Mode);
		this.policiesByName = new WeakHashMap<String, CachedElement<Map<String, List<NamespacePolicy>>>>(150);
		this.policiesByHash = new WeakHashMap<String, CachedElement<Map<String, List<NamespacePolicy>>>>(150);
		this.directory = directory;
		this.updateInterval = updateInterval;
	}
	
	@Override
	public void setPolicies(Collection<String> locations)
	{
	}

	@Override
	protected List<NamespacePolicy> getPoliciesByIssuerHash(String definedForHash,
			String issuerHash)
	{
		String path = directory + File.separator + definedForHash + SUFFIX;
		return getCachedPolicies(policiesByHash, definedForHash, issuerHash, path, updateInterval);
	}

	@Override
	protected List<NamespacePolicy> getPoliciesByIssuerDn(String definedForHash, String issuerDn)
	{
		String path = directory + File.separator + definedForHash + SUFFIX;
		return getCachedPolicies(policiesByName, definedForHash, issuerDn, path, updateInterval);
	}
}
