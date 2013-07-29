/*
 * Copyright (c) 2011 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.ns;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import eu.emi.security.authn.x509.NamespaceCheckingMode;
import eu.emi.security.authn.x509.ValidationError;
import eu.emi.security.authn.x509.ValidationErrorCode;
import eu.emi.security.authn.x509.impl.X500NameUtils;
import eu.emi.security.authn.x509.proxy.ProxyUtils;

/**
 * Implements namespace policy checking. The class is populated with a namespace policy store
 * which provides the policies. The implementation gets  
 * 
 * 
 * @author K. Benedyczak
 */
public class NamespaceChecker
{
	private boolean namespaceRequired;
	private boolean checkAll;
	private NamespacesStore[] nsStores;

	public NamespaceChecker(NamespaceCheckingMode mode, NamespacesStore pmaStore, 
			NamespacesStore globusStore)
	{
		namespaceRequired = mode.isRequired();
		checkAll = (mode == NamespaceCheckingMode.EUGRIDPMA_AND_GLOBUS || 
				mode == NamespaceCheckingMode.EUGRIDPMA_AND_GLOBUS_REQUIRE);
		int used = 0;
		if (mode.globusEnabled())
			used++;
		if (mode.euGridPmaEnabled())
			used++;
		nsStores = new NamespacesStore[used];
		if (mode.isGlobusFirst())
		{
			nsStores[0] = globusStore;
			if (mode.euGridPmaEnabled())
				nsStores[1] = pmaStore;
		} else
		{
			if (mode.euGridPmaEnabled())
				nsStores[0] = pmaStore;
			if (mode.globusEnabled())
				nsStores[1] = globusStore;
		}
	}
	
	/**
	 * Checks all certificates in the chain whether they are correct w.r.t. namespace policies
	 * which are configured. If the parameter contains any proxy certificates those are ignored.
	 * Self signed certificates in the chain are ignored, so the root CA certificate may be safely 
	 * present in the chain. 
	 * @param chain to be checked
	 */
	public List<ValidationError> check(X509Certificate[] chain)
	{
		if (nsStores.length == 0)
			return Collections.emptyList();
		List<ValidationError> ret = new ArrayList<ValidationError>();
		
		for (int i=0; i<chain.length; i++)
		{
			boolean found = false;
			X500Principal certIssuer = chain[i].getIssuerX500Principal();
			X500Principal certSubject = chain[i].getSubjectX500Principal();
			if (certIssuer.equals(certSubject))
				continue;
			if (ProxyUtils.isProxy(chain[i]))
				continue;
			
			for (NamespacesStore nsStore: nsStores)
			{
				List<NamespacePolicy> policies = nsStore.getPolicies(chain, i);
				if (policies == null || policies.size() == 0)
					continue;
				found = true;
				doCheck(certSubject, policies, ret, i, chain);
				if (!checkAll)
					break;
			}
			if (!found && namespaceRequired)
			{
				ret.add(new ValidationError(chain, i, ValidationErrorCode.nsUndefinedAndRequired,  
						X500NameUtils.getReadableForm(certIssuer)));
			}
		}
		return ret;
	}
	
	private void doCheck(X500Principal subject, List<NamespacePolicy> policies, 
			List<ValidationError> ret, int pos, X509Certificate[] chain)
	{
		boolean permitFound = false;
		StringBuilder policyNames = new StringBuilder();
		for (NamespacePolicy policy: policies)
		{
			policyNames.append(policy.getIdentification()).append(" ");
			if (policy.isSubjectMatching(subject))
			{
				if (!policy.isPermit())
					ret.add(new ValidationError(chain, pos, ValidationErrorCode.nsDeny, 
							X500NameUtils.getReadableForm(subject),							 
							policy.getIdentification()));
				else
					permitFound = true;
			}
		}
		
		if (!permitFound)
		{
			ret.add(new ValidationError(chain, pos, ValidationErrorCode.nsNotAccepted, 
					X500NameUtils.getReadableForm(subject),
					policyNames.toString()));
		}
	}
}
