/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.ns;

import static junit.framework.Assert.assertEquals;
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
	
	public Case(String file, String[] issuers, String[][] permitted)
	{
		if (issuers.length != permitted.length)
			throw new IllegalArgumentException("Wrong params");
		this.file = file;
		this.issuers = issuers;
		this.permitted = permitted;
	}
	
	
	public void checkContains(String perm, int issuer)
	{
		for (String aval: permitted[issuer])
		{
			if (aval.equals(perm))
				return;
		}
		fail(perm + " not found in expected");
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
			assertNotNull(result);
			assertEquals(issuer, permitted[i].length, result.size());
			for (int j=0; j<result.size(); j++)
			{
				NamespacePolicy np = result.get(j);
				if (np.getIssuer().contains("="))
					assertEquals(issuers[i], np.getIssuer());
				checkContains(np.getSuject(), i);
			}
		}
	}
}