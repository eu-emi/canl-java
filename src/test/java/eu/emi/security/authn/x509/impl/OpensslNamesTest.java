/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.impl;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class OpensslNamesTest {
	private void testOpensslInt(String rfc, String expected, boolean globusMode)
	{
		String result = OpensslNameUtils.convertFromRfc2253(rfc, globusMode);
		
		System.out.println(rfc);
		System.out.println(expected);
		System.out.println(result);
		assertEquals(expected.toLowerCase(), result.toLowerCase());
	}
	
	@Test
	public void testOpensslConversion()
	{
		String dn1, dn1Openssl;

		dn1 = "2.5.4.3.3.2.222=#030300FEFF";
		dn1Openssl = "/2.5.4.3.3.2.222=\\xFE\\xFF";
		testOpensslInt(dn1, dn1Openssl, false);
		
		dn1 = "CN=qweółą";
		dn1Openssl = "/CN=qwe\\xC3\\xB3\\xC5\\x82\\xC4\\x85";
		testOpensslInt(dn1, dn1Openssl, false);
		
		dn1 = "2.5.4.3.3.2.222=#038180008182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF,O=org2,2.5.4.3.3.2.222=#0C152C225C2B3D3C3E3B616C61C3B3C582C485C59BC487,C=PL,CN=Krzys/O\\=ICM";
		dn1Openssl = "/CN=Krzys/O=ICM/C=PL/2.5.4.3.3.2.222=,\"\\+=<>;ala\\xC3\\xB3\\xC5\\x82\\xC4\\x85\\xC5\\x9B\\xC4\\x87/O=org2/2.5.4.3.3.2.222=\\x81\\x82\\x83\\x84\\x85\\x86\\x87\\x88\\x89\\x8A\\x8B\\x8C\\x8D\\x8E\\x8F\\x90\\x91\\x92\\x93\\x94\\x95\\x96\\x97\\x98\\x99\\x9A\\x9B\\x9C\\x9D\\x9E\\x9F\\xA0\\xA1\\xA2\\xA3\\xA4\\xA5\\xA6\\xA7\\xA8\\xA9\\xAA\\xAB\\xAC\\xAD\\xAE\\xAF\\xB0\\xB1\\xB2\\xB3\\xB4\\xB5\\xB6\\xB7\\xB8\\xB9\\xBA\\xBB\\xBC\\xBD\\xBE\\xBF\\xC0\\xC1\\xC2\\xC3\\xC4\\xC5\\xC6\\xC7\\xC8\\xC9\\xCA\\xCB\\xCC\\xCD\\xCE\\xCF\\xD0\\xD1\\xD2\\xD3\\xD4\\xD5\\xD6\\xD7\\xD8\\xD9\\xDA\\xDB\\xDC\\xDD\\xDE\\xDF\\xE0\\xE1\\xE2\\xE3\\xE4\\xE5\\xE6\\xE7\\xE8\\xE9\\xEA\\xEB\\xEC\\xED\\xEE\\xEF\\xF0\\xF1\\xF2\\xF3\\xF4\\xF5\\xF6\\xF7\\xF8\\xF9\\xFA\\xFB\\xFC\\xFD\\xFE\\xFF";
		testOpensslInt(dn1, dn1Openssl, false);

		dn1 = "CN=Krzys/O\\=ICM";
		dn1Openssl = "/CN=Krzys/O=ICM";
		testOpensslInt(dn1, dn1Openssl, false);

		dn1 = "EMAIL=a@b,E=b@c,EMAILADDRESS=c@d,generation=2nd";
		dn1Openssl = "/generationQualifier=2nd/emailAddress=c@d/emailAddress=b@c/emailAddress=a@b";
		testOpensslInt(dn1, dn1Openssl, false);

		
		//doesn't make sense to test multivalued - this is a roulette
		//dn1="DC=ggg+O=zzz+C=aaa";
		//dn1Openssl="/C=aaa+O=zzz+DC=ggg";
		//testOpensslInt(dn1, dn1Openssl, true);
	}
	
	@Test
	public void testOpensslNormalization()
	{
		String dn1, dn1Openssl;

		dn1 = "2.5.4.3.3.2.222=#0C152C225C2B3D3C3E3B616C61C3B3C582C485C59BC487,EMAIL=a@b,E=b@c,EMAILADDRESS=c@d,generation=2nd";
		dn1Openssl = "/generationQualifier=2nd/emailAddress=c@d/emailAddress=b@c/emailAddress=a@b/2.5.4.3.3.2.222=,\"\\+=<>;ala\\xC3\\xB3\\xC5\\x82\\xC4\\x85\\xC5\\x9B\\xC4\\x87";

		assertEquals(OpensslNameUtils.normalize(dn1Openssl), OpensslNameUtils.normalize(
				OpensslNameUtils.convertFromRfc2253(dn1, false)));
		
		dn1 = "/C=EU/E=email@ee.net/EMAIL=email2@ee.net/EmailAddress=email@ee.net/givenname=aLa";
		dn1Openssl = "/c=eu/emailaddress=email@ee.net/emailaddress=email2@ee.net/emailaddress=email@ee.net/gn=ala";
		
		assertEquals(dn1Openssl, OpensslNameUtils.normalize(dn1));
	}
}
