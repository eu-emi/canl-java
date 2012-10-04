/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.impl;

import java.util.Random;

import org.junit.Test;

import eu.emi.security.authn.x509.NamespaceCheckingMode;


public class OpensslValidatorStressTest
{
	@Test
	public void testValidator() throws Exception
	{
		Random r = new Random();
		for (int i=0; i<500; i++) 
		{
			OpensslCertChainValidator validator1 = new OpensslCertChainValidator(
					"src/test/resources/glite-utiljava/grid-security/certificates",
					NamespaceCheckingMode.EUGRIDPMA_GLOBUS, r.nextInt(3), 
					new ValidatorParamsExt());
			validator1.dispose();
		}
	}
}