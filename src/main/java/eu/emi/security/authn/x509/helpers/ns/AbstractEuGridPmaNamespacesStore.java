/*
 * Copyright (c) 2011 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.ns;

import java.util.ArrayList;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import eu.emi.security.authn.x509.StoreUpdateListener;
import eu.emi.security.authn.x509.helpers.ObserversHandler;
import eu.emi.security.authn.x509.helpers.trust.OpensslTruststoreHelper;
import eu.emi.security.authn.x509.impl.OpensslNameUtils;

/**
 * EuGridPMA policy store common code. Defines parsers and constants required to load the .namespaces files.
 * <p>  
 * This class it thread safe.
 * 
 * @author K. Benedyczak
 */
public abstract class AbstractEuGridPmaNamespacesStore extends AbstractNamespacesStore
{
	public static final String SUFFIX = ".namespaces";
	
	public AbstractEuGridPmaNamespacesStore(ObserversHandler observers, boolean openssl1Mode)
	{
		super(observers, openssl1Mode);
	}

	@Override
	protected String getNotificationType()
	{
		return StoreUpdateListener.EUGRIDPMA_NAMESPACE;
	}
	
	@Override
	protected NamespacesParser getParser(String path)
	{
		return new EuGridPmaNamespacesParser(path, openssl1Mode);
	}
	
	@Override
	protected String getFileSuffix()
	{
		return SUFFIX;
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
			
			List<NamespacePolicy> byHash = getPoliciesByIssuerHash(definedForHash, issuerHash);
			List<NamespacePolicy> byName = getPoliciesByIssuerDn(definedForHash, normalizedDn);
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
	
	protected abstract List<NamespacePolicy> getPoliciesByIssuerHash(String definedForHash, String issuerHash);
	protected abstract List<NamespacePolicy> getPoliciesByIssuerDn(String definedForHash, String issuerDn);
}
