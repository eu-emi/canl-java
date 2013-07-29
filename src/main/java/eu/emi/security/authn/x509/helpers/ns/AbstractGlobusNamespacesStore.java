/*
 * Copyright (c) 2011 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.ns;

import java.util.List;

import javax.security.auth.x500.X500Principal;

import eu.emi.security.authn.x509.StoreUpdateListener;
import eu.emi.security.authn.x509.helpers.ObserversHandler;
import eu.emi.security.authn.x509.helpers.trust.OpensslTruststoreHelper;
import eu.emi.security.authn.x509.impl.OpensslNameUtils;

/**
 * Globus EACL policy store common code. Defines parsers and constants required to load the EACL files.
 * <p>  
 * This class it thread safe.
 * 
 * @author K. Benedyczak
 */
public abstract class AbstractGlobusNamespacesStore extends AbstractNamespacesStore
{
	public static final String SUFFIX = ".signing_policy";
	
	public AbstractGlobusNamespacesStore(ObserversHandler observers, boolean openssl1Mode)
	{
		super(observers, openssl1Mode);
	}

	@Override
	protected String getNotificationType()
	{
		return StoreUpdateListener.EACL_NAMESPACE;
	}
	
	@Override
	protected NamespacesParser getParser(String path)
	{
		return new GlobusNamespacesParser(path);
	}
	
	@Override
	protected String getFileSuffix()
	{
		return SUFFIX;
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
			String hash = OpensslTruststoreHelper.getOpenSSLCAHash(issuer, openssl1Mode);
			
			List<NamespacePolicy> ret = getPoliciesFor(hash, normalizedDn);
			if (ret != null)
				return ret;
		}
		return null;
	}
	
	protected abstract List<NamespacePolicy> getPoliciesFor(String definedForHash, String issuerDn);
}
