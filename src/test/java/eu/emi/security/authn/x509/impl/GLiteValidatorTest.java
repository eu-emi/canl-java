/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 *
 * Derived from the code copyrighted and licensed as follows:
 * 
 * Copyright (c) Members of the EGEE Collaboration. 2004.
 * See http://www.eu-egee.org/partners/ for details on the copyright
 * holders.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *    http://www.apache.org/licenses/LICENSE-2.0
 *    
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package eu.emi.security.authn.x509.impl;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;

import org.junit.Assert;
import org.junit.Test;

import eu.emi.security.authn.x509.CrlCheckingMode;
import eu.emi.security.authn.x509.NamespaceCheckingMode;
import eu.emi.security.authn.x509.OCSPCheckingMode;
import eu.emi.security.authn.x509.OCSPParametes;
import eu.emi.security.authn.x509.ProxySupport;
import eu.emi.security.authn.x509.RevocationParameters;
import eu.emi.security.authn.x509.StoreUpdateListener;
import eu.emi.security.authn.x509.ValidationError;
import eu.emi.security.authn.x509.ValidationResult;
import eu.emi.security.authn.x509.impl.CertificateUtils.Encoding;


public class GLiteValidatorTest
{
	private static final TestCase[] trustedTestCases = {
			new TestCase("trusted-certs/trusted_client", false, true),
			new TestCase("trusted-certs/trusted_client_exp", false, false),
			new TestCase("trusted-certs/trusted_clientserver", false, true),
			new TestCase("trusted-certs/trusted_clientserver_exp", false, false),
			new TestCase("trusted-certs/trusted_fclient", false, true),
			new TestCase("trusted-certs/trusted_fclient_exp", false, false),
			new TestCase("trusted-certs/trusted_none", false, true),
			new TestCase("trusted-certs/trusted_none_exp", false, false),
			new TestCase("trusted-certs/trusted_server", false, true),
			new TestCase("trusted-certs/trusted_server_exp", false, false)
	};
	
	private static final TestCase[] trustedRevokedTestCases = {
			new TestCase("trusted-certs/trusted_client_rev", false, false),
			new TestCase("trusted-certs/trusted_clientserver_rev", false, false),
			new TestCase("trusted-certs/trusted_fclient_rev", false, false),
			new TestCase("trusted-certs/trusted_none_rev", false, false),
			new TestCase("trusted-certs/trusted_server_rev", false, false)
	};
	
	private static final TestCase[] trustedProxiesTestCases = {
			new TestCase("trusted-certs/trusted_client_exp.proxy.grid_proxy", true, false),
			new TestCase("trusted-certs/trusted_client.proxy.grid_proxy", true, true),
			new TestCase("trusted-certs/trusted_client.proxy_exp.grid_proxy", true, false),
			new TestCase("trusted-certs/trusted_clientserver_exp.proxy.grid_proxy", true, false),
			new TestCase("trusted-certs/trusted_clientserver.proxy.grid_proxy", true, true),
			new TestCase("trusted-certs/trusted_clientserver.proxy_exp.grid_proxy", true, false),
			new TestCase("trusted-certs/trusted_fclient_exp.proxy.grid_proxy", true, false),
			new TestCase("trusted-certs/trusted_fclient.proxy.grid_proxy", true, true),
			new TestCase("trusted-certs/trusted_fclient.proxy_exp.grid_proxy", true, false),
			new TestCase("trusted-certs/trusted_none_exp.proxy.grid_proxy", true, false),
			new TestCase("trusted-certs/trusted_none.proxy.grid_proxy", true, true),
			new TestCase("trusted-certs/trusted_none.proxy_exp.grid_proxy", true, false),
			new TestCase("trusted-certs/trusted_server_exp.proxy.grid_proxy", true, false),
			new TestCase("trusted-certs/trusted_server.proxy.grid_proxy", true, true),
			new TestCase("trusted-certs/trusted_server.proxy_exp.grid_proxy", true, false),
			new TestCase("trusted-certs/trusted_client.proxy_rfc.grid_proxy", true, true),
			new TestCase("trusted-certs/trusted_client.proxy_rfc_plen.proxy_rfc.proxy_rfc.grid_proxy", true, false),
			new TestCase("trusted-certs/trusted_client.proxy_rfc_plen.proxy_rfc.grid_proxy", true, true),
			new TestCase("trusted-certs/trusted_client.proxy_rfc_lim.grid_proxy", true, true),
			new TestCase("trusted-certs/trusted_client.proxy_rfc.proxy.grid_proxy", true, false),
			new TestCase("trusted-certs/trusted_client.proxy_rfc_lim.proxy_rfc.grid_proxy", true, false),
			new TestCase("trusted-certs/trusted_client.proxy_rfc.proxy_rfc_lim.grid_proxy", true, true),
			new TestCase("trusted-certs/trusted_client.proxy_rfc_anyp.grid_proxy", true, true),
			new TestCase("trusted-certs/trusted_client.proxy_rfc_indep.grid_proxy", true, true)
	};
	
	private static final TestCase[] trustedRevokedProxiesTestCases = {
			new TestCase("trusted-certs/trusted_client_rev.proxy.grid_proxy", true, false),
			new TestCase("trusted-certs/trusted_clientserver_rev.proxy.grid_proxy", true, false),
			new TestCase("trusted-certs/trusted_fclient_rev.proxy.grid_proxy", true, false),
			new TestCase("trusted-certs/trusted_none_rev.proxy.grid_proxy", true, false),
			new TestCase("trusted-certs/trusted_server_rev.proxy.grid_proxy", true, false)
	};
	
	private static final TestCase[] fakeCertsTestCases = {
			new TestCase("fake-certs/fake_client", false, false),
			new TestCase("fake-certs/fake_client.proxy", false, false)
	};
	
	private static final TestCase[] fakeProxiesTestCases = {
			new TestCase("fake-certs/fake_client.proxy.grid_proxy", true, false)
	};
	
	private static final TestCase[] miscProxiesTestCases = {
			new TestCase("trusted-certs/trusted_client.proxy_dnerror2.grid_proxy", true, false),
			new TestCase("trusted-certs/trusted_client.proxy_dnerror.grid_proxy", true, false),
			new TestCase("trusted-certs/trusted_client.proxy_dnerror.proxy.grid_proxy", true, false),
			new TestCase("trusted-certs/trusted_client.proxy.proxy_dnerror.grid_proxy", true, false),
			new TestCase("trusted-certs/trusted_client.proxy_exp.proxy.grid_proxy", true, false),
			new TestCase("trusted-certs/trusted_client.proxy_exp.proxy_exp.grid_proxy", true, false),
			new TestCase("trusted-certs/trusted_client.proxy.proxy_exp.grid_proxy", true, false),
			new TestCase("trusted-certs/trusted_client.proxy.proxy.grid_proxy", true, true),
			new TestCase("trusted-certs/trusted_bigclient",false, true)
	};
	
	private static final TestCase[] subsubProxiesTestCases = {
			new TestCase("subsubca-certs/subsubca_fullchainclient.proxy.grid_proxy", true, true),
			new TestCase("subsubca-certs/subsubca_fullchainclient.proxy.proxy.grid_proxy", true, true),
			new TestCase("subsubca-certs/subsubca_client.proxy.grid_proxy", true, true),
			new TestCase("subsubca-certs/subsubca_client.proxy.proxy.grid_proxy", true, true)
	};
	
	private static final TestCase[] subsubRevokedProxiesTestCases = {
			new TestCase("subsubca-certs/subsubca_client_rev.proxy.grid_proxy", true, false),
			new TestCase("subsubca-certs/subsubca_client_rev.proxy.proxy.grid_proxy", true, false)
	};

	private static final TestCase[] subsubBadDNProxiesTestCases = {
			new TestCase("subsubca-certs/subsubca_clientbaddn.proxy.grid_proxy", true, false),
			new TestCase("subsubca-certs/subsubca_clientbaddn.proxy.proxy.grid_proxy", true, false)
	};
	
	private static final TestCase[] bigProxiesTestCases = {
			new TestCase("big-certs/big_client.proxy.grid_proxy", true, true),
			new TestCase("big-certs/big_client.proxy.proxy.grid_proxy", true, true)
	};

	protected void gliteTest(boolean reverse, TestCase tc,
			String trustStore, boolean revocation, boolean openssl1Mode)
	{
		try
		{
			gliteTestInternalWithOpensslStore(reverse, tc, trustStore, revocation, openssl1Mode);
		} catch (Exception e)
		{
			e.printStackTrace();
			Assert.fail("Exception when processing " + tc.name
					+ ": " + e);
		}
	}
	
	protected void gliteTestInternalWithOpensslStore(boolean reverse, TestCase tc, 
			String trustStore, boolean revocation, boolean openssl1Mode) throws Exception
	{
		System.out.println("Test Case: " + tc.name);
		
		X509Certificate[] toCheck;
		if (tc.isProxy)
		{
			KeyStore ks = CertificateUtils.loadPEMKeystore(new FileInputStream(
				"src/test/resources/glite-utiljava/" + tc.name), 
				(char[])null, "test".toCharArray());
			toCheck = CertificateUtils.convertToX509Chain(
				ks.getCertificateChain(CertificateUtils.DEFAULT_KEYSTORE_ALIAS));
		} else
		{
			toCheck = new X509Certificate[] {
					CertificateUtils.loadCertificate(new FileInputStream(
					"src/test/resources/glite-utiljava/" + tc.name + ".cert"), 
					Encoding.PEM) };
		}
		int expectedErrors = 0;
		boolean expectedResult = tc.valid;
		if (reverse)
			expectedResult = !expectedResult;
		if (!expectedResult)
			expectedErrors = Integer.MAX_VALUE;
		StoreUpdateListener l = new StoreUpdateListener()
		{
			@Override
			public void loadingNotification(String location, String type,
					Severity level, Exception cause)
			{
				if (level.equals(Severity.ERROR))
				{
					Assert.fail("Error reading a truststore: " + 
							location + " " + type + " " + cause);
				}
			}
		};
		List<StoreUpdateListener> listeners = Collections.singletonList(l);
		
		ValidatorParams params = new ValidatorParams(new RevocationParameters(revocation ? 
						CrlCheckingMode.REQUIRE : CrlCheckingMode.IF_VALID, 
				new OCSPParametes(OCSPCheckingMode.IGNORE)), 
				tc.isProxy ? ProxySupport.ALLOW : ProxySupport.DENY, listeners);
		OpensslCertChainValidator validator = new OpensslCertChainValidator(
				"src/test/resources/glite-utiljava/grid-security/"+trustStore+"/",
				openssl1Mode,
				NamespaceCheckingMode.EUGRIDPMA, 
				-1, 
				params);
		
		ValidationResult result = validator.validate(toCheck);
		List<ValidationError> errors = result.getErrors();
		
		if (!result.isValid())
		{
			System.out.println("Result (short): " + result.toShortString());
			System.out.println("Result (full) : " + result);
		}
		
		if (expectedErrors == Integer.MAX_VALUE)
			Assert.assertTrue("Certificate validated successfully while should get error", errors.size() > 0);
		else
			Assert.assertEquals(expectedErrors, errors.size());
		validator.dispose();
	}

	
	
	private static class TestCase
	{
		private String name;
		private boolean valid;
		private boolean isProxy;
		public TestCase(String name, boolean isProxy, boolean valid)
		{
			this.name = name;
			this.valid = valid;
			this.isProxy = isProxy;
		}
	}
	
	@Test
	public void test1()
	{
		String truststore = "certificates";
		boolean revocation = true;
		boolean openssl1Mode = false;
		
		for (TestCase tc: trustedTestCases)
			gliteTest(false, tc, truststore, revocation, openssl1Mode);
		for (TestCase tc: trustedRevokedTestCases)
			gliteTest(false, tc, truststore, revocation, openssl1Mode);
		for (TestCase tc: trustedProxiesTestCases)
			gliteTest(false, tc, truststore, revocation, openssl1Mode);
		for (TestCase tc: trustedRevokedProxiesTestCases)
			gliteTest(false, tc, truststore, revocation, openssl1Mode);
		for (TestCase tc: fakeCertsTestCases)
			gliteTest(false, tc, truststore, revocation, openssl1Mode);
		for (TestCase tc: fakeProxiesTestCases)
			gliteTest(false, tc, truststore, revocation, openssl1Mode);
		for (TestCase tc: miscProxiesTestCases)
			gliteTest(false, tc, truststore, revocation, openssl1Mode);
		for (TestCase tc: subsubProxiesTestCases)
			gliteTest(false, tc, truststore, revocation, openssl1Mode);
		for (TestCase tc: subsubRevokedProxiesTestCases)
			gliteTest(false, tc, truststore, revocation, openssl1Mode);
		for (TestCase tc: subsubBadDNProxiesTestCases)
			gliteTest(false, tc, truststore, revocation, openssl1Mode);
		for (TestCase tc: bigProxiesTestCases)
			gliteTest(false, tc, truststore, revocation, openssl1Mode);
	}

	@Test
	public void test1WithNewHash()
	{
		String truststore = "certificates-newhash-all";
		boolean revocation = true;
		boolean openssl1Mode = true;

		for (TestCase tc: trustedTestCases)
			gliteTest(false, tc, truststore, revocation, openssl1Mode);
		for (TestCase tc: trustedRevokedTestCases)
			gliteTest(false, tc, truststore, revocation, openssl1Mode);
		for (TestCase tc: trustedProxiesTestCases)
			gliteTest(false, tc, truststore, revocation, openssl1Mode);
		for (TestCase tc: trustedRevokedProxiesTestCases)
			gliteTest(false, tc, truststore, revocation, openssl1Mode);
		for (TestCase tc: fakeCertsTestCases)
			gliteTest(false, tc, truststore, revocation, openssl1Mode);
		for (TestCase tc: fakeProxiesTestCases)
			gliteTest(false, tc, truststore, revocation, openssl1Mode);
		for (TestCase tc: miscProxiesTestCases)
			gliteTest(false, tc, truststore, revocation, openssl1Mode);
		for (TestCase tc: subsubProxiesTestCases)
			gliteTest(false, tc, truststore, revocation, openssl1Mode);
		for (TestCase tc: subsubRevokedProxiesTestCases)
			gliteTest(false, tc, truststore, revocation, openssl1Mode);
		for (TestCase tc: subsubBadDNProxiesTestCases)
			gliteTest(false, tc, truststore, revocation, openssl1Mode);
		for (TestCase tc: bigProxiesTestCases)
			gliteTest(false, tc, truststore, revocation, openssl1Mode);
	}

	
	@Test
	public void test2()
	{
		String truststore = "certificates-withoutCrl";
		boolean revocation = false;
		boolean openssl1Mode = false;

		for (TestCase tc: trustedTestCases)
			gliteTest(false, tc, truststore, revocation, openssl1Mode);
		for (TestCase tc: trustedRevokedTestCases)
			gliteTest(true, tc, truststore, revocation, openssl1Mode);
		for (TestCase tc: trustedProxiesTestCases)
			gliteTest(false, tc, truststore, revocation, openssl1Mode);
		for (TestCase tc: trustedRevokedProxiesTestCases)
			gliteTest(true, tc, truststore, revocation, openssl1Mode);
		for (TestCase tc: fakeCertsTestCases)
			gliteTest(false, tc, truststore, revocation, openssl1Mode);
		for (TestCase tc: fakeProxiesTestCases)
			gliteTest(false, tc, truststore, revocation, openssl1Mode);
		for (TestCase tc: miscProxiesTestCases)
			gliteTest(false, tc, truststore, revocation, openssl1Mode);
		for (TestCase tc: subsubProxiesTestCases)
			gliteTest(false, tc, truststore, revocation, openssl1Mode);
		for (TestCase tc: subsubRevokedProxiesTestCases)
			gliteTest(true, tc, truststore, revocation, openssl1Mode);
		for (TestCase tc: subsubBadDNProxiesTestCases)
			gliteTest(false, tc, truststore, revocation, openssl1Mode);
		for (TestCase tc: bigProxiesTestCases)
			gliteTest(false, tc, truststore, revocation, openssl1Mode);
	}

	@Test
	public void test3()
	{
		String truststore = "certificates-withoutCrl";
		boolean revocation = true;
		boolean openssl1Mode = false;
		gliteTest(true, trustedTestCases[0], truststore, revocation, openssl1Mode);
		gliteTest(false, trustedRevokedTestCases[0], truststore, revocation, openssl1Mode);
	}

	@Test
	public void test4()
	{
		String truststore = "certificates-rootwithpolicy";
		boolean revocation = false;
		boolean openssl1Mode = false;
		for (TestCase tc: subsubProxiesTestCases)
			gliteTest(false, tc, truststore, revocation, openssl1Mode);
		for (TestCase tc: subsubRevokedProxiesTestCases)
			gliteTest(false, tc, truststore, revocation, openssl1Mode);
		for (TestCase tc: subsubBadDNProxiesTestCases)
			gliteTest(false, tc, truststore, revocation, openssl1Mode);
	}
	
	@Test
	public void test5()
	{
		String truststore = "certificates-subcawithpolicy";
		boolean revocation = false;
		boolean openssl1Mode = false;
		
		for (TestCase tc: subsubProxiesTestCases)
			gliteTest(false, tc, truststore, revocation, openssl1Mode);
		for (TestCase tc: subsubRevokedProxiesTestCases)
			gliteTest(false, tc, truststore, revocation, openssl1Mode);
		for (TestCase tc: subsubBadDNProxiesTestCases)
			gliteTest(false, tc, truststore, revocation, openssl1Mode);
	}	

	@Test
	public void test6()
	{
		String truststore = "certificates-rootallowsubsubdeny";
		boolean revocation = false;
		boolean openssl1Mode = false;
		for (TestCase tc: subsubProxiesTestCases)
			gliteTest(true, tc, truststore, revocation, openssl1Mode);
		for (TestCase tc: subsubRevokedProxiesTestCases)
			gliteTest(false, tc, truststore, revocation, openssl1Mode);
		for (TestCase tc: subsubBadDNProxiesTestCases)
			gliteTest(false, tc, truststore, revocation, openssl1Mode);
	}
	
	@Test
	public void testSlash()
	{
		String truststore = "certificates";
		boolean revocation = false;
		boolean openssl1Mode = false;
		TestCase slash = new TestCase("slash-certs/slash_client_slash", false, true);
		gliteTest(false, slash, truststore, revocation, openssl1Mode);
	}
}
