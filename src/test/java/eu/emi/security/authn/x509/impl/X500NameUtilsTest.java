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
