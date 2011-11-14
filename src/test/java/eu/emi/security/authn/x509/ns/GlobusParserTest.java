/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.ns;

import java.io.File;
import java.io.IOException;
import java.util.List;

import static junit.framework.Assert.*;

import org.junit.Test;

import eu.emi.security.authn.x509.helpers.CertificateHelpers;
import eu.emi.security.authn.x509.helpers.ns.GlobusNamespacesParser;
import eu.emi.security.authn.x509.helpers.ns.GlobusNamespacesStore;
import eu.emi.security.authn.x509.helpers.ns.NamespacePolicy;
import eu.emi.security.authn.x509.impl.X500NameUtils;

public class GlobusParserTest
{
	public static final String PFX = "src/test/resources/namespaces/";
	
	private static Case[] CORRECT_TEST_CASES = {
		new Case(PFX + "correct.signing_policy",
				new String[] {
				"CN=AAA Certificate Services,O=Test Organization,C=EU",
				"EMAILADDRESS=email@ee.net,EMAILADDRESS=email2@ee.net,EMAILADDRESS=email@ee.net,C=EU",
				"CN=CA2,C=EU",
				"CN=CA3,C=EU",
				"CN=CA4,C=EU",
				"CN=CA5,C=EU"},
				new String[][] {
				{"\\QCN=AAA Certificate Services,O=Test Organization,C=EU\\E",
					"\\QCN=Client Authentication and Email,OU=http://www.example.com,O=Test Organization,C=EU\\E"},
				{"\\QEMAILADDRESS=email@ee.net,EMAILADDRESS=email2@ee.net,EMAILADDRESS=email@ee.net,C=EU\\E"},
				{".*\\Q,EMAILADDRESS=email@ee.net,C=\\E..",
					".*\\Q,EMAILADDRESS=email@ee.net,O=Test,C=EU\\E"},
				{".*\\Q,EMAILADDRESS=email@ee.net,C=\\E.."},
				{".*\\Q,EMAILADDRESS=email@ee.net,C=\\E.."},
				{".*\\Q,CN=\\E.*\\Q,C=EU\\E",
					"\\QCN=\\E.*\\Q,C=EU\\E"}
				})
	};

	private static String[] INCORRECT_TEST_CASES = {
		PFX+"incorrect1.signing_policy",
		PFX+"incorrect2.signing_policy",
		PFX+"incorrect3.signing_policy",
		PFX+"incorrect4.signing_policy",
		PFX+"incorrect5.signing_policy"
	};
	
	
	
	@Test
	public void testOpensslDNParser()
	{
		String rfc = CertificateHelpers.opensslToRfc2253("/C=GB/ST=Greater Manchester/L=Salford/O=Comodo CA Limited/CN=AAA Certificate Services");
		
		System.out.println(rfc);
		System.out.println(X500NameUtils.getReadableForm(rfc));
		assertEquals("CN=AAA Certificate Services,O=Comodo CA Limited,L=Salford,ST=Greater Manchester,C=GB", 
				rfc);
		
		rfc = CertificateHelpers.opensslToRfc2253("/C=US/ST=UT/L=Salt Lake City/O=The USERTRUST Network/OU=http://www.usertrust.com/CN=UTN-USERFirst-Client Authentication and Email");
		
		System.out.println(rfc);
		System.out.println(X500NameUtils.getReadableForm(rfc));
		assertEquals("CN=UTN-USERFirst-Client Authentication and Email,OU=http://www.usertrust.com,O=The USERTRUST Network,L=Salt Lake City,ST=UT,C=US", 
				rfc);
		
		rfc = CertificateHelpers.opensslToRfc2253("/C=??/E=email@ee.net/*", true);
		System.out.println(rfc);
		assertEquals("*,E=email@ee.net,C=??", rfc);
		
		rfc = CertificateHelpers.opensslToRfc2253("/C=US/CN=Company, Inc.");
		System.out.println(rfc);
		System.out.println(X500NameUtils.getReadableForm(rfc));
		assertEquals("CN=Company\\, Inc.,C=US", rfc);
	}
	
	@Test
	public void testRegExpConverter()
	{
		String pattern = GlobusNamespacesParser.makeRegexpClassicWildcard("*,E*=?ail@?*?.net,C=??*");
		assertEquals(".*\\Q,E\\E.*\\Q=\\E.\\Qail@\\E..*.\\Q.net,C=\\E...*", pattern);
	}
	
	@Test
	public void testNormalizer() throws IOException
	{
		List<String> pattern = GlobusNamespacesParser.normalize(
				"/C=EU/CN=*");
		assertEquals(".*\\Q,CN=\\E.*\\Q,C=EU\\E", pattern.get(1));
		assertEquals("\\QCN=\\E.*\\Q,C=EU\\E", pattern.get(0));
	}
	
	@Test
	public void testEuGridPMADistro()
	{
		File f = new File(PFX+"eugridpma-globus");
		String []files = f.list();
		for (String file: files)
		{
			File toTest = new File(f, file);
			if (toTest.isDirectory())
				continue;
			System.out.println("Testing file " + file);
			GlobusNamespacesParser parser = new GlobusNamespacesParser(
					f.getPath()+File.separator+file);
			GlobusNamespacesStore store = new GlobusNamespacesStore();
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
	public void testCorrect()
	{
		for (Case testCase: CORRECT_TEST_CASES)
		{
			System.out.println("Testing file " + testCase.file);
			GlobusNamespacesParser parser = new GlobusNamespacesParser(testCase.file);
			GlobusNamespacesStore store = new GlobusNamespacesStore();
			testCase.testCase(store, parser);
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
