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
import java.security.cert.X509Certificate;

import javax.net.ssl.HandshakeCompletedEvent;

import static org.junit.Assert.*;
import org.junit.Test;

import eu.emi.security.authn.x509.impl.CertificateUtils.Encoding;

public class HostnameCheckerTest
{
	public final String PFX = "src/test/resources/glite-utiljava/trusted-certs/";
	
	public class HostnameCheckerImpl extends AbstractHostnameToCertificateChecker
	{
		@Override
		protected void nameMismatch(HandshakeCompletedEvent hce,
				X509Certificate peerCertificate, String hostName)
		{
		}
	}
	
	@Test
	public void testPattern()
	{
		System.out.println(AbstractHostnameToCertificateChecker.makeRegexpHostWildcard(
				"*.aaa.*dd.ss*.*.dd*dd*dd*.[a-zA-Z]+.*"));
		
		System.out.println(AbstractHostnameToCertificateChecker.matchesDNS(
				"a.aaa.dd.sss.a.ddaaddaaddaaa.aaa.d",
				"*.aaa.*dd.ss*.*.dd*dd*dd*.[a-zA-Z]+.*"));
	}

	@Test
	public void testMatching() throws Exception
	{
		AbstractHostnameToCertificateChecker checker = new HostnameCheckerImpl();
		
		X509Certificate altnameCert = CertificateUtils.loadCertificate(
				new FileInputStream(PFX + "trusted_altname.cert"),
				Encoding.PEM);
		assertTrue(checker.checkMatching("ja.hoo.org", altnameCert));
		assertTrue(checker.checkMatching("joo.haa.org", altnameCert));
		assertTrue(checker.checkMatching("123.124.220.1", altnameCert));
		assertTrue(checker.checkMatching("ga.easda.com", altnameCert));
		assertFalse(checker.checkMatching("da.easda.com", altnameCert));
		assertFalse(checker.checkMatching("123.124.220.12", altnameCert));
		assertFalse(checker.checkMatching("xxx.foo.bar", altnameCert));
		assertFalse(checker.checkMatching("ja.ja.hoo.org", altnameCert));

		
		X509Certificate altname2Cert = CertificateUtils.loadCertificate(
				new FileInputStream(PFX + "trusted_altname_2.cert"),
				Encoding.PEM);
		assertTrue(checker.checkMatching("ja.hoo.org", altname2Cert));
		assertTrue(checker.checkMatching("joo.haa.org", altname2Cert));
		assertTrue(checker.checkMatching("123.124.220.1", altname2Cert));
		assertTrue(checker.checkMatching("ga.easda.com", altname2Cert));
		assertFalse(checker.checkMatching("da.easda.com", altname2Cert));
		assertFalse(checker.checkMatching("123.124.220.12", altname2Cert));
		assertFalse(checker.checkMatching("xxx.foo.bar", altname2Cert));
		assertFalse(checker.checkMatching("ja.ja.hoo.org", altname2Cert));

		
		X509Certificate dnsDNCert = CertificateUtils.loadCertificate(
				new FileInputStream(PFX + "trusted_server2.cert"),
				Encoding.PEM);
		assertFalse(checker.checkMatching("ja.hoo.org", dnsDNCert));
		assertFalse(checker.checkMatching("joo.haa.org", dnsDNCert));
		assertFalse(checker.checkMatching("123.124.220.1", dnsDNCert));
		assertFalse(checker.checkMatching("ga.easda.com", dnsDNCert));
		assertFalse(checker.checkMatching("da.easda.com", dnsDNCert));
		assertFalse(checker.checkMatching("123.124.220.12", dnsDNCert));
		assertTrue(checker.checkMatching("xxx2.foo.bar", dnsDNCert));
		assertFalse(checker.checkMatching("ja.ja.hoo.org", dnsDNCert));

		
		X509Certificate cert = CertificateUtils.loadCertificate(
				new FileInputStream("src/test/resources/glite-utiljava/input/hostcert-email.pem"),
				Encoding.PEM);
		assertTrue(checker.checkMatching("wilco.cnaf.infn.it", cert));
		assertFalse(checker.checkMatching("xxx.cnaf.infn.it", cert));

			
		X509Certificate cert2 = CertificateUtils.loadCertificate(
					new FileInputStream(PFX + "trusted_host_email.cert"),
					Encoding.PEM);
		assertTrue(checker.checkMatching("pchip10.cern.ch", cert2));
		assertTrue(checker.checkMatching("pchip10.cern.ch", cert2));
		assertFalse(checker.checkMatching("xxx.cnaf.infn.it", cert2));

		
		X509Certificate cert3 = CertificateUtils.loadCertificate(
					new FileInputStream(PFX + "trusted_altname3_2.cert"),
					Encoding.PEM);
		assertTrue(checker.checkMatching("pchip10.cern.ch", cert3));
		assertTrue(checker.checkMatching("pchip10.cern.ch", cert3));
		assertFalse(checker.checkMatching("xxx.cnaf.infn.it", cert3));
	}
}
