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
 * Globus EACL policies are loaded on demand by this store and are cached in memory. A
 * weak hash map is used to cache data. Additionally the data is cached for no longer then the 
 * update interval, which in practice is the same as for the cooperating truststore.
 * <p>  
 * This class it thread safe.
 * 
 * @author K. Benedyczak
 */
public class LazyGlobusNamespacesStore extends AbstractGlobusNamespacesStore
{
	/**
	 * This structure holds the namespaces cache. The primary map key is the hash
	 * name of the file from which some of the policies were loaded. At the same time it is a hash of the subject
	 * name of the CA for which the namespaces were directly defined.
	 * The internal map is indexed with issuer names, i.e. the names of the CA subjects for which we have policies.
	 * The value is a list with all the policies for the CA, in order of appearance in the policy file.
	 */
	protected Map<String, CachedElement<Map<String, List<NamespacePolicy>>>> policiesByName;
	protected final String directory;
	protected final long updateInterval;

	public LazyGlobusNamespacesStore(ObserversHandler observers, boolean openssl1Mode, String directory,
			long updateInterval)
	{
		super(observers, openssl1Mode);
		this.policiesByName = new WeakHashMap<String, CachedElement<Map<String, List<NamespacePolicy>>>>(1);
		this.directory = directory;
		this.updateInterval = updateInterval;
	}
	
	@Override
	public void setPolicies(Collection<String> locations)
	{
	}

	@Override
	protected List<NamespacePolicy> getPoliciesFor(String definedForHash, String issuerDn)
	{
		String path = directory + File.separator + definedForHash + SUFFIX;
		return getCachedPolicies(policiesByName, definedForHash, issuerDn, path, updateInterval);
	}
}
