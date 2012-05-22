/*
 * Copyright (c) 2011 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.impl;

import static org.junit.Assert.*;

import java.io.IOException;

import javax.security.auth.x500.X500Principal;

import junit.framework.Assert;

import org.bouncycastle.asn1.x500.style.BCStyle;
import org.junit.Test;

import eu.emi.security.authn.x509.helpers.DNComparator;


public class X500NameUtilsTest
{
	private static final String DN1 = "1.3.6.1.4.1.42.2.11.2.1=127.0.0.1, CN=Tomasz Hajto+CN=Tomasz Wałdoch,C=PL";
	private static final String DN2 = "1.2.840.113549.1.9.1=#160b666f6f406261722e6e6574,DC=a,DC=B,    C=PL";
	private static final String DN3 = "1.2.840.113549.1.9.1=#160b666f6f406261722e6e6574,DC=a,DC=B,EMAIL=a@b+E=b@c,C=PL";

	private void testOpensslInt(String rfc, String expected, boolean globusMode)
	{
		String result = X500NameUtils.getOpensslLegacyForm(rfc, globusMode);
		
		System.out.println(rfc);
		System.out.println(expected);
		System.out.println(result);
		assertEquals(expected, result);
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
		
		dn1 = "2.5.4.3.3.2.222=#038180008182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF,O=org2,2.5.4.3.3.2.222=#0C152C225C2B3D3C3E3B616C61C3B3C582C485C59BC487,C=PL,CN=Krzys/O=ICM";
		dn1Openssl = "/CN=Krzys/O=ICM/C=PL/2.5.4.3.3.2.222=,\"\\+=<>;ala\\xC3\\xB3\\xC5\\x82\\xC4\\x85\\xC5\\x9B\\xC4\\x87/O=org2/2.5.4.3.3.2.222=\\x81\\x82\\x83\\x84\\x85\\x86\\x87\\x88\\x89\\x8A\\x8B\\x8C\\x8D\\x8E\\x8F\\x90\\x91\\x92\\x93\\x94\\x95\\x96\\x97\\x98\\x99\\x9A\\x9B\\x9C\\x9D\\x9E\\x9F\\xA0\\xA1\\xA2\\xA3\\xA4\\xA5\\xA6\\xA7\\xA8\\xA9\\xAA\\xAB\\xAC\\xAD\\xAE\\xAF\\xB0\\xB1\\xB2\\xB3\\xB4\\xB5\\xB6\\xB7\\xB8\\xB9\\xBA\\xBB\\xBC\\xBD\\xBE\\xBF\\xC0\\xC1\\xC2\\xC3\\xC4\\xC5\\xC6\\xC7\\xC8\\xC9\\xCA\\xCB\\xCC\\xCD\\xCE\\xCF\\xD0\\xD1\\xD2\\xD3\\xD4\\xD5\\xD6\\xD7\\xD8\\xD9\\xDA\\xDB\\xDC\\xDD\\xDE\\xDF\\xE0\\xE1\\xE2\\xE3\\xE4\\xE5\\xE6\\xE7\\xE8\\xE9\\xEA\\xEB\\xEC\\xED\\xEE\\xEF\\xF0\\xF1\\xF2\\xF3\\xF4\\xF5\\xF6\\xF7\\xF8\\xF9\\xFA\\xFB\\xFC\\xFD\\xFE\\xFF";
		testOpensslInt(dn1, dn1Openssl, false);
		
		//doesn't make sense to test multivalued - this is a roulette
		//dn1="DC=ggg+O=zzz+C=aaa";
		//dn1Openssl="/C=aaa+O=zzz+DC=ggg";
		//testOpensslInt(dn1, dn1Openssl, true);
	}
	
	@Test
	public void testPrint()
	{
		String rf = X500NameUtils.getReadableForm(DN1);
		assertEquals("IP=127.0.0.1,CN=Tomasz Hajto+CN=Tomasz Wałdoch,C=PL", rf);
		rf = X500NameUtils.getReadableForm(DN2);
		assertEquals("EMAILADDRESS=foo@bar.net,DC=a,DC=B,C=PL", rf);
		rf = X500NameUtils.getReadableForm("");
		assertEquals("", rf);
	}
	
	@Test
	public void testGetValues()
	{
		String[] ret = X500NameUtils.getAttributeValues(DN2, BCStyle.E);
		assertEquals(1, ret.length);
		assertEquals("foo@bar.net", ret[0]);
		
		ret = X500NameUtils.getAttributeValues(DN3, BCStyle.E);
		assertEquals(3, ret.length);
		assertEquals("foo@bar.net", ret[0]);
		assertEquals("a@b", ret[1]);
		assertEquals("b@c", ret[2]);
	}
	
	/**
	 *  
	 *  CN      commonName (2.5.4.3)
	 *  L       localityName (2.5.4.7)
	 *  ST      stateOrProvinceName (2.5.4.8)
	 *  O       organizationName (2.5.4.10)
	 *  OU      organizationalUnitName (2.5.4.11)
	 *  C       countryName (2.5.4.6)
	 *  STREET  streetAddress (2.5.4.9)
	 *  DC      domainComponent (0.9.2342.19200300.100.1.25)
	 *  UID     userId (0.9.2342.19200300.100.1.1)
	 */
	@Test
	public void testDNs()
	{
		String dnA[] = {
				"CN=James \\\"Jim\\\" Smith\\, III,DC=net,L=Before\0dAfter,1.3.6.1.4.1.1466.0=#04024869,ST=Lu\\C4\\8Di\\C4\\87,O=org,OU=OtherUnit,C=Country+STREET=Multi valued Avenue+0.9.2342.19200300.100.1.1=multiValuedUid,EMAIL=email@is.also.recognized",
				"CN=James \\\"Jim\\\" Smith\\, III,DC=NET,L=Before\0dAfter,1.3.6.1.4.1.1466.0=#04024869,ST=Lu\\C4\\8Di\\C4\\87,O=org,OU=OtherUnit,C=Country+STREET=Multi valued Avenue+0.9.2342.19200300.100.1.1=multiValuedUid,EMAIL=email@is.ALSO.recognized",
				"CN=James \\\"Jim\\\" Smith\\, III, DC=net,L=Before\0dAfter,1.3.6.1.4.1.1466.0=#04024869,ST=Lu\\C4\\8Di\\C4\\87,O=org,OU=OtherUnit,C=Country+STREET=Multi valued Avenue+0.9.2342.19200300.100.1.1=multivaluedUid,EMAIL=email@is.also.recognized",
		};
		
		checkAll(true, dnA);
		
		String src = "CN=Ala ma kota, DC=nEt,EMAIL=golBi@localhost+DC=FFFF+C=PL,DC=kkL,EMAILADDRESS=ss@asddsfdsDDDD";
		String normalized = DNComparator.preNormalize(src);
		X500Principal x500 = new X500Principal(normalized);
		String dnB[] = {
				src,
				normalized,
				x500.getName(),
				x500.getName(X500Principal.CANONICAL),
				new X500Principal(src).getName(),
				new X500Principal(src).getName(X500Principal.CANONICAL)
		};
		
		checkAll(true, dnB);
		
		String dn1 = "EMAIL=e@at";
		String dn2 = "EMAIL=E@At";
		dn1 = new X500Principal(dn1).getName(X500Principal.CANONICAL);
		dn2 = new X500Principal(dn2).getName(X500Principal.CANONICAL);
		
		assertTrue(X500NameUtils.equal(dn1, dn2));
	}
	
	private void checkAll(boolean mode, String []dn)
	{
		for (int i=0; i<dn.length; i++)
			for (int j=0; j<dn.length; j++)
			{
				boolean res = X500NameUtils.equal(dn[i], dn[j]);
				
				if (mode && !res)
				{
					String msg = "DN " + i + " and " + j + " reported to be different.";
					System.err.println(msg);
					fail(msg);
				}
				if (!mode && res)
				{
					String msg = "DN " + i + " and " + j + " reported to be equivalent.";
					System.err.println(msg);
					fail(msg);
				}
			}
	}
	
	@Test
	public void test()
	{
		try
		{
			X500Principal x500 = X500NameUtils.getX500Principal("CN=a,O=test,EMAIL=some@email.net,Gender=FEMALE");
			Assert.assertEquals("CN=a, O=test, EMAILADDRESS=some@email.net, OID.1.3.6.1.5.5.7.9.3=FEMALE", 
					x500.toString());
		} catch (IOException e)
		{
			e.printStackTrace();
			Assert.fail(e.toString());
		}
	}
}
