/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.ns;

import static junit.framework.Assert.assertNotNull;
import static junit.framework.Assert.fail;

import java.io.IOException;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import eu.emi.security.authn.x509.helpers.ns.NamespacePolicy;
import eu.emi.security.authn.x509.helpers.ns.NamespacesParser;
import eu.emi.security.authn.x509.helpers.ns.NamespacesStore;
import eu.emi.security.authn.x509.impl.X500NameUtils;

public class Case
{
	String file;
	String[] issuers;
	String[][] permitted;
	String[][] denied;
	
	public Case(String file, String[] issuers, String[][] permitted, String[][] denied)
	{
		if (issuers.length != permitted.length)
			throw new IllegalArgumentException("Wrong params");
		this.file = file;
		this.issuers = issuers;
		this.permitted = permitted;
		this.denied = denied;
	}
	
	
	public void checkContains(List<NamespacePolicy> nps, int issuer) throws IOException
	{
		for (String aval: permitted[issuer])
		{
			boolean found = false;
			for (NamespacePolicy np: nps)
				if (np.isSubjectMatching(X500NameUtils.getX500Principal(aval)))
				{
					found = true;
					break;
				}
			if (!found)
				fail(aval + " not permitted by the policy as expected");
		}
	}

	public void checkNotContains(List<NamespacePolicy> nps, int issuer) throws IOException
	{
		for (String aval: denied[issuer])
		{
			for (NamespacePolicy np: nps)
				if (np.isSubjectMatching(X500NameUtils.getX500Principal(aval)))
					fail(aval + " permitted by the policy while expected deny");
		}
	}
	
	public void testCase(NamespacesStore store, NamespacesParser parser)
	{
		List<NamespacePolicy> result;
		try
		{
			result = parser.parse();
		} catch (IOException e)
		{
			e.printStackTrace();
			fail(e.toString());
			return; //dummy
		}
		store.setPolicies(result);
		
		for (int i=0; i<issuers.length; i++)
		{
			String issuer = issuers[i];
			X500Principal issuerP;
			try
			{
				issuerP = X500NameUtils.getX500Principal(issuer);
			} catch (IOException e)
			{
				e.printStackTrace();
				fail(e.toString());
				return; //dummy
			}
			result = store.getPolicies(issuerP);
			assertNotNull("Got no NSP for " + issuerP, result);
			try
			{
				checkContains(result, i);
				checkNotContains(result, i);
			} catch (IOException e)
			{
				e.printStackTrace();
				fail(e.toString());
			}
		}
	}
}