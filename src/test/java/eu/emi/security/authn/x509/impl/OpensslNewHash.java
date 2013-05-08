/*
 * Copyright (c) 2013 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.impl;

import javax.security.auth.x500.X500Principal;

import junit.framework.Assert;

import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.junit.Test;

import eu.emi.security.authn.x509.helpers.trust.OpensslTrustAnchorStore;

/**
 * Tests related to openssl 1.0.0 new subject hashes support
 * @author K. Benedyczak
 */
public class OpensslNewHash
{
	@Test
	public void test() throws Exception
	{
		X500Principal subject = new X500Principal("  CN=Polish    Grid CA,O=GRID,C=PL   ");
		RDN[] c19nrdns = OpensslTrustAnchorStore.getNormalizedRDNs(subject);

		X500Name newName = new X500Name(c19nrdns);
		X500Principal newSubject = new X500Principal(newName.getEncoded());
		System.out.println("After: '" + newSubject.getName() +"'");
		String hash = OpensslTrustAnchorStore.getOpenSSLCAHash(subject, true);
		System.out.println("hash: " + hash);
		Assert.assertEquals("03b260e0", hash);
	}
}
