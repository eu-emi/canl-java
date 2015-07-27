/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.impl;

import java.io.FileInputStream;
import java.security.cert.X509Certificate;
import java.util.Random;

import junit.framework.Assert;

import org.junit.Test;

import eu.emi.security.authn.x509.NamespaceCheckingMode;
import eu.emi.security.authn.x509.ValidationResult;
import eu.emi.security.authn.x509.impl.CertificateUtils.Encoding;


public class OpensslValidatorStressTest
{
	@Test
	public void testSpeedup() throws Exception
	{
		OpensslCertChainValidator greedyValidatorWarmup = new OpensslCertChainValidator(
				"src/test/resources/glite-utiljava/grid-security/certificates", false,
				NamespaceCheckingMode.EUGRIDPMA_GLOBUS, 100000, 
				new ValidatorParamsExt(), false);
		OpensslCertChainValidator lazyValidatorWarmup = new OpensslCertChainValidator(
				"src/test/resources/glite-utiljava/grid-security/certificates", false,
				NamespaceCheckingMode.EUGRIDPMA_GLOBUS, 100000, 
				new ValidatorParamsExt(), true);

		
		long start = System.currentTimeMillis();
		for (int i=0; i<500; i++) 
		{
			OpensslCertChainValidator validator1 = new OpensslCertChainValidator(
					"src/test/resources/glite-utiljava/grid-security/certificates", false,
					NamespaceCheckingMode.EUGRIDPMA_GLOBUS, 1000, 
					new ValidatorParamsExt(), false);
			validator1.dispose();
		}
		long t1 = System.currentTimeMillis() - start;
		
		start = System.currentTimeMillis();
		for (int i=0; i<500; i++) 
		{
			OpensslCertChainValidator validator1 = new OpensslCertChainValidator(
					"src/test/resources/glite-utiljava/grid-security/certificates", false,
					NamespaceCheckingMode.EUGRIDPMA_GLOBUS, 1000, 
					new ValidatorParamsExt(), true);
			validator1.dispose();
		}
		long t2 = System.currentTimeMillis() - start;
		double speedup = (double)t1/t2;
		System.out.println("Loading: greedy: " + t1 + "ms  lazy: " + t2 + "ms; speedup: " + speedup);
		Assert.assertTrue("Speedup of lazy truststore loading is not sufficient", speedup > 50.0);
		
		X509Certificate[] toCheck = CertificateUtils.loadCertificateChain(new FileInputStream(
				"src/test/resources/glite-utiljava/trusted-certs/trusted_client.cert"), 
				Encoding.PEM);
	}

	//@Test
	public void testMemoryOOMValidator() throws Exception
	{
		Random rand = new Random();
		Runtime r = Runtime.getRuntime();
		r.gc();
		long usedMem1 = r.totalMemory() - r.freeMemory();
		for (int i=0; i<2000; i++) 
		{
			new OpensslCertChainValidator(
					"src/test/resources/glite-utiljava/grid-security/certificates",
					false,
					NamespaceCheckingMode.EUGRIDPMA_GLOBUS, rand.nextInt(3), 
					new ValidatorParamsExt(), false);
			if (i%100 == 0)
			{
				r.gc();
				long usedMem2 = r.totalMemory() - r.freeMemory();
				System.out.println("Used memory: " + usedMem2/1024 + "kB\t\tChange: " + 
						(usedMem2-usedMem1)/1024 + "kB");
			}
		}
		r.gc();
		long usedMem2 = r.totalMemory() - r.freeMemory();
		if (usedMem2-usedMem1 > 20000000)
			Assert.fail("Memory leak? Usage stats are: " + usedMem1 + " " + usedMem2 + " " 
					+ (usedMem2-usedMem1));
		else
			System.out.println("Memory usage stats are: " + usedMem1 + " " + usedMem2 + " " 
					+ (usedMem2-usedMem1));
	}
}


