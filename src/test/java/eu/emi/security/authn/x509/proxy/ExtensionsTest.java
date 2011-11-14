/*
 * Copyright (c) 2011 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.proxy;

import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERObject;
import static org.junit.Assert.*;
import org.junit.Test;

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
}
