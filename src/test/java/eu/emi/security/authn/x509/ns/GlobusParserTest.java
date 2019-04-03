/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.ns;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.io.File;
import java.io.IOException;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.junit.Test;

import eu.emi.security.authn.x509.helpers.ObserversHandler;
import eu.emi.security.authn.x509.helpers.ns.GlobusNamespacesParser;
import eu.emi.security.authn.x509.helpers.ns.GlobusNamespacesParser.InvalidPolicyFilenameException;
import eu.emi.security.authn.x509.helpers.ns.GlobusNamespacesStore;
import eu.emi.security.authn.x509.helpers.ns.NamespacePolicy;

public class GlobusParserTest
{
	public static final String PFX = "src/test/resources/namespaces/";
	
	private static Case[] CORRECT_TEST_CASES = {
		new Case(PFX + "f2089c29.0",
				new String[] {
				"CN=AAA Certificate Services,O=Test Organization,C=EU",
				"EMAILADDRESS=email@ee.net,EMAILADDRESS=email2@ee.net,EMAILADDRESS=email@ee.net,C=EU",
				"CN=CA2,C=EU",
				"CN=CA3,C=EU",
				"CN=CA4,C=EU",
				"CN=CA5,C=EU"},
				new String[][] {
				{"CN=AAA Certificate Services,O=Test Organization,C=EU",
				 "CN=Client Authentication and Email,OU=http://www.example.com,O=Test Organization,C=EU"},
				{"EMAILADDRESS=email@ee.net,EMAILADDRESS=email2@ee.net,EMAILADDRESS=email@ee.net,C=EU"},
				{"CN=aa,S=bb,EMAILADDRESS=email@ee.net,C=XY",
				 "SN=1,EMAILADDRESS=email@ee.net,C=ZZ",
				 "SN=2,EMAILADDRESS=email@ee.net,O=Test,C=EU"},
				{"SN=2,EMAILADDRESS=email@ee.net,C=AU"},
				{"SN=2,EMAILADDRESS=email@ee.net,C=AU"},
				{"CN=alala,C=EU",
				 "CN=,C=EU",
				 "CN=asdsa,CN=qaa,C=EU"}
				},
				new String[][] {
				{"CN=AAA Certificate Services,O=Test Organization"},
				{"EMAILADDRESS=email@ee.net,EMAILADDRESS=email2@ee.net,EMAILADDRESS=email@ee.net,C=PL"},
				{"CN=aa,S=bb,EMAILADDRESS=email@ee.net,C=XYZ",
				 "CN=x,EMAILADDRESS=email@ee.net,C=X"},
				{},
				{},
				{"C=EU"}
				}
		)
	};

	private static String[] INCORRECT_TEST_CASES = {
		PFX+"20000001.signing_policy",
		PFX+"20000002.signing_policy",
		PFX+"20000003.signing_policy",
		PFX+"20000004.signing_policy",
		PFX+"20000005.signing_policy"
	};
	
	
	
//	@Test
//	public void testOpensslDNParser()
//	{
//		String rfc = CertificateHelpers.opensslToRfc2253("/C=GB/ST=Greater Manchester/L=Salford/O=Comodo CA Limited/CN=AAA Certificate Services");
//		
//		System.out.println(rfc);
//		System.out.println(X500NameUtils.getReadableForm(rfc));
//		assertEquals("CN=AAA Certificate Services,O=Comodo CA Limited,L=Salford,ST=Greater Manchester,C=GB", 
//				rfc);
//		
//		rfc = CertificateHelpers.opensslToRfc2253("/C=US/ST=UT/L=Salt Lake City/O=The USERTRUST Network/OU=http://www.usertrust.com/CN=UTN-USERFirst-Client Authentication and Email");
//		
//		System.out.println(rfc);
//		System.out.println(X500NameUtils.getReadableForm(rfc));
//		assertEquals("CN=UTN-USERFirst-Client Authentication and Email,OU=http://www.usertrust.com,O=The USERTRUST Network,L=Salt Lake City,ST=UT,C=US", 
//				rfc);
//		
//		rfc = CertificateHelpers.opensslToRfc2253("/C=??/E=email@ee.net/*", true);
//		System.out.println(rfc);
//		assertEquals("*,E=email@ee.net,C=??", rfc);
//		
//		rfc = CertificateHelpers.opensslToRfc2253("/C=US/CN=Company, Inc.");
//		System.out.println(rfc);
//		System.out.println(X500NameUtils.getReadableForm(rfc));
//		assertEquals("CN=Company\\, Inc.,C=US", rfc);
//	}
	
	@Test
	public void testRegExpConverter()
	{
		String pattern = GlobusNamespacesParser.makeRegexpClassicWildcard("*,E*=?ail@?*?.net,C=??*");
		assertEquals(".*\\Q,E\\E.*\\Q=\\E.\\Qail@\\E..*.\\Q.net,C=\\E...*", pattern);
	}
	
	@Test
	public void testEuGridPMADistro()
	{
		File directory = new File(PFX + "eugridpma-globus");
		String []files = directory.list();
		int correct = 0;
		for (String file: files)
		{
			File toTest = new File(directory, file);
			if (toTest.isDirectory())
				continue;
			
			System.out.println("Testing file " + file);
			GlobusNamespacesParser parser = new GlobusNamespacesParser(toTest.getAbsolutePath());
			try
			{
				List<NamespacePolicy> policy = parser.parse();
				assertThat(policy.isEmpty(), is(false));
				correct++;
			} catch (InvalidPolicyFilenameException e)
			{
				//OK - ignored, we have garbage in the test directory
			} catch (IOException e)
			{
				e.printStackTrace();
				fail("Failed to parse signing policy " + file);
			}
		}
		assertThat(correct, is(200));
	}
		
	@Test
	public void testCorrect()
	{
		X500Principal rootP = new X500Principal("CN=AAA Certificate Services,O=Test Organization,C=EU");
		ObserversHandler observers = new ObserversHandler();
		for (Case testCase: CORRECT_TEST_CASES)
		{
			System.out.println("Testing file " + testCase.file);
			GlobusNamespacesStore store = new GlobusNamespacesStore(observers, false);
			testCase.testCase(store, testCase.file, rootP);
		}
	}
	
	@Test
	public void testIncorrect()
	{
		for (String testCase: INCORRECT_TEST_CASES)
		{
			GlobusNamespacesParser parser = new GlobusNamespacesParser(testCase);
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
