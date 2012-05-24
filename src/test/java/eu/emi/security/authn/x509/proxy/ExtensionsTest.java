/*
 * Copyright (c) 2011 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.proxy;

import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERObject;
import static org.junit.Assert.*;

import org.junit.Test;

import eu.emi.security.authn.x509.helpers.proxy.IPAddressHelper;

/**
 * @author K. Benedyczak
 */
public class ExtensionsTest
{
	@Test
	public void certificateExtTest()
	{
		DERIA5String string = new DERIA5String("ala");
		CertificateExtension ce = new CertificateExtension("0.1.2.3.4.5", string, true);
		DERObject der = ce.getDERObject();
		
		CertificateExtension parsed = new CertificateExtension(der.getDEREncoded());
		assertTrue(parsed.isCritical());
		assertEquals("0.1.2.3.4.5", parsed.getOid());
		assertEquals(string, parsed.getValue());
	}
	
	@Test
	public void ipMatcherTest()
	{
		byte[] space1 = {(byte)192,(byte)168,12,0, 	(byte)255,(byte)255,(byte)255,0};
		byte[] space2 = {(byte)192,(byte)168,12,0, 	(byte)255,(byte)255,(byte)254,0};
		byte[] space3 = {(byte)192,(byte)168,(byte)128,0, 	(byte)255,(byte)255,(byte)192,0};
		
		byte[] addr1 = new byte[] {(byte)192,(byte)168,12,20};
		byte[] addr2 = new byte[] {(byte)192,(byte)168,13,(byte)129};
		byte[] addr3 = new byte[] {(byte)192,(byte)168,1,1};
		byte[] addr4 = new byte[] {(byte)192,(byte)168,14,1};
		byte[] addr5 = new byte[] {(byte)192,(byte)168,(byte)144,13};

		assertTrue(IPAddressHelper.isWithinAddressSpace(addr1, space1));
		assertTrue(IPAddressHelper.isWithinAddressSpace(addr1, space2));
		
		assertFalse(IPAddressHelper.isWithinAddressSpace(addr2, space1));
		assertTrue(IPAddressHelper.isWithinAddressSpace(addr2, space2));

		assertFalse(IPAddressHelper.isWithinAddressSpace(addr3, space1));
		assertFalse(IPAddressHelper.isWithinAddressSpace(addr3, space2));
		
		assertFalse(IPAddressHelper.isWithinAddressSpace(addr4, space3));
		assertTrue(IPAddressHelper.isWithinAddressSpace(addr5, space3));
	}
	
	@Test
	public void ipMatcherTestIPv6()
	{
		byte[] space1 = {(byte)192,(byte)168,12,0,(byte)192,(byte)168,12,0,(byte)192,(byte)168,12,0,(byte)192,(byte)168,(byte)192,0,
				(byte)255,(byte)255,(byte)255,(byte)255,(byte)255,(byte)255,(byte)255,(byte)255,(byte)255,(byte)255,(byte)255,(byte)255,(byte)255,(byte)255,(byte)192,0};
		
		byte[] addr1 = new byte[] {(byte)192,(byte)168,12,0,(byte)192,(byte)168,12,0,(byte)192,(byte)168,12,0,(byte)192,(byte)168,(byte)252,122};
		byte[] addr2 = new byte[] {(byte)192,(byte)168,12,0,(byte)192,(byte)168,12,0,(byte)192,(byte)168,12,0,(byte)192,(byte)168,(byte)191,122};

		assertTrue(IPAddressHelper.isWithinAddressSpace(addr1, space1));
		assertFalse(IPAddressHelper.isWithinAddressSpace(addr2, space1));
	}

}
