/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.impl;

import java.util.Random;

import junit.framework.Assert;

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

	@Test
	public void testMemoryOOMValidator() throws Exception
	{
		Runtime r = Runtime.getRuntime();
		r.gc();
		long usedMem1 = r.totalMemory() - r.freeMemory();
		for (int i=0; i<500; i++) 
		{
			new OpensslCertChainValidator(
					"src/test/resources/glite-utiljava/grid-security/certificates",
					NamespaceCheckingMode.EUGRIDPMA_GLOBUS, 10000, 
					new ValidatorParamsExt());
		}
		r.gc();
		long usedMem2 = r.totalMemory() - r.freeMemory();
		if (usedMem2-usedMem1 > 4000000)
			Assert.fail("Memory leak? Usage stats are: " + usedMem1 + " " + usedMem2 + " " 
					+ (usedMem2-usedMem1));
	}
}