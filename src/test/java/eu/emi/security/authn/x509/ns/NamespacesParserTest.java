/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.ns;

import java.io.File;
import java.io.IOException;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import static junit.framework.Assert.*;

import org.junit.Test;

import eu.emi.security.authn.x509.helpers.ns.EuGridPmaNamespacesParser;
import eu.emi.security.authn.x509.helpers.ns.EuGridPmaNamespacesStore;
import eu.emi.security.authn.x509.helpers.ns.NamespacePolicy;
import eu.emi.security.authn.x509.impl.X500NameUtils;

public class NamespacesParserTest
{
	public static final String PFX = "src/test/resources/namespaces/";
	
	private static Case[] CORRECT_TEST_CASES = {
		new Case(PFX + "4798da47.namespaces",
				new String[] {
				"CN=HKU Grid CA,DC=GRID,DC=HKU,DC=HK",
				"CN=Test,C=EU",
				"CN=http://www.net.org,C=EU",
				},
				new String[][] {
				{"OU=sadsa,O=ddd,CN=sdsss,C=EU", 
				 "CN=aasda,C=EU", 
				 "SN=sdfas,CN=sdaaa,O=t,C=EU", 
				 "CN=ddsadsa,O=t,C=EU"},
				{"c=ll,dc=ola,CN=zzz,O=q,C=EU", 
				 "CN=sdasd,O=q,C=EU", 
				 "E=a@b,CN=sada,UID=sdas,S=dd,C=Ed", 
				 "CN=sss,l=sds,C=Ej"},
				{"CN=ha\\,ha \\,ha,EMAILADDRESS=c@d,EMAILADDRESS=a@b,EMAILADDRESS=some@email"},
				},
				new String[][] {
				{"SN=sdsss,C=EU"},
				{"SN=sdfas,CN=sdaaa,O=t,C=EU,O=foo"},
				{}
				})
	};

	private static String[] INCORRECT_TEST_CASES = {
		PFX+"00000001.namespaces",
		PFX+"00000002.namespaces",
		PFX+"00000003.namespaces",
		PFX+"00000004.namespaces",
		PFX+"00000005.namespaces",
		PFX+"00000006.namespaces"
	};
	
	
	@Test
	public void testEuGridPMADistro()
	{
		File f = new File(PFX+"eugridpma-namespaces");
		String []files = f.list();
		for (String file: files)
		{
			File toTest = new File(f, file);
			if (toTest.isDirectory())
				continue;
			System.out.println("Testing file " + file);
			EuGridPmaNamespacesParser parser = new EuGridPmaNamespacesParser(
					f.getPath()+File.separator+file, false);
			EuGridPmaNamespacesStore store = new EuGridPmaNamespacesStore(false);
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
		}
	}

	@Test
	public void testInheritance()
	{
		EuGridPmaNamespacesParser parser = new EuGridPmaNamespacesParser("src/test/resources/namespaces/4798da47.namespaces", false);
		EuGridPmaNamespacesStore store = new EuGridPmaNamespacesStore(false);
		try
		{
			List<NamespacePolicy> parsed = parser.parse();
			parser = new EuGridPmaNamespacesParser("src/test/resources/namespaces/62faf355.namespaces", false);
			parsed.addAll(parser.parse());
			store.setPolicies(parsed);
			List<NamespacePolicy> p1 = store.getPolicies(new X500Principal[]{X500NameUtils.getX500Principal(
					"CN=HKU Grid CA,DC=GRID,DC=HKU,DC=HK")}, 0);
			assertEquals(2, p1.size());
			List<NamespacePolicy> p2 = store.getPolicies(new X500Principal[]{
					X500NameUtils.getX500Principal("CN=Test,C=EU"), 
					X500NameUtils.getX500Principal("CN=HKU Grid CA,DC=GRID,DC=HKU,DC=HK")}, 0);
			assertEquals(1, p2.size());
			
		} catch (IOException e)
		{
			e.printStackTrace();
			fail(e.toString());
		}
	}
	
	@Test
	public void testCorrect() throws IOException
	{
		X500Principal rootP = X500NameUtils.getX500Principal("CN=HKU Grid CA,DC=GRID,DC=HKU,DC=HK");
		for (Case testCase: CORRECT_TEST_CASES)
		{
			System.out.println("Testing file " + testCase.file);
			EuGridPmaNamespacesParser parser = new EuGridPmaNamespacesParser(testCase.file, false);
			EuGridPmaNamespacesStore store = new EuGridPmaNamespacesStore(false);
			testCase.testCase(store, parser, rootP);
		}
	}
	
	@Test
	public void testIncorrect()
	{
		for (String testCase: INCORRECT_TEST_CASES)
		{
			EuGridPmaNamespacesParser parser = new EuGridPmaNamespacesParser(testCase, false);
			try
			{
				parser.parse();
				fail("Should get an error but parsing was successful, file " + testCase);
			} catch (IOException e)
			{
				//OK
				System.out.println("Got an expected error for file " + testCase + 
						": " + e.getMessage());
			}
		}
	}
}
