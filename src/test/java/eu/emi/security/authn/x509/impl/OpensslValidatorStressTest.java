/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.impl;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import java.io.FileInputStream;
import java.security.cert.X509Certificate;
import java.util.Random;

import org.junit.Assert;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import eu.emi.security.authn.x509.NamespaceCheckingMode;
import eu.emi.security.authn.x509.RiskyIntegrationTests;
import eu.emi.security.authn.x509.impl.CertificateUtils.Encoding;


public class OpensslValidatorStressTest
{
	@Test
	@Category(RiskyIntegrationTests.class)
	public void testSpeedup() throws Exception
	{
		new OpensslCertChainValidator(
				"src/test/resources/glite-utiljava/grid-security/certificates", false,
				NamespaceCheckingMode.EUGRIDPMA_GLOBUS, 100000, 
				new ValidatorParamsExt(), false);
		new OpensslCertChainValidator(
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
	}

	
	@Test
	@Category(RiskyIntegrationTests.class)
	public void opensslValidationShouldBeParallel() throws Exception
	{
		final OpensslCertChainValidator validator = new OpensslCertChainValidator(
				"src/test/resources/glite-utiljava/grid-security/certificates", false,
				NamespaceCheckingMode.EUGRIDPMA_GLOBUS, 100000, 
				new ValidatorParamsExt(), false);
		final X509Certificate[] toCheck = CertificateUtils.loadCertificateChain(new FileInputStream(
				"src/test/resources/glite-utiljava/trusted-certs/trusted_client.cert"), 
				Encoding.PEM);

		final int THREADS = 4;
		final int OPERATIONS = 2000;

		long linearDuration = runValidation(1, OPERATIONS, validator, toCheck);
		long parallelDuration = runValidation(THREADS, OPERATIONS/THREADS, validator, toCheck);
		
		System.out.println("Linear duration: " + linearDuration + "ms, " + 
				OPERATIONS*1000.0/linearDuration + "ops");
		System.out.println("Parallel duration: " + parallelDuration + "ms, " + 
				OPERATIONS*1000.0/parallelDuration + "ops");
		assertThat(1.4*parallelDuration < linearDuration, is(true));
	}
	
	private long runValidation(int threadsNum, final int loop, final OpensslCertChainValidator validator,
			final X509Certificate[] toCheck) throws InterruptedException
	{
		Thread []threads = new Thread[threadsNum];
		long start = System.currentTimeMillis();
		for (int i=0; i<threadsNum; i++)
		{
			threads[i] = new Thread(new Runnable(){
				@Override
				public void run()
				{
					for (int j=0; j<loop; j++)
						assertThat(validator.validate(toCheck).isValid(), is(true));
				}
			});
			threads[i].start();
		}
		for (int i=0; i<threadsNum; i++)
			threads[i].join();
		return System.currentTimeMillis() - start;
	}
	
	
	@Test
	@Category(RiskyIntegrationTests.class)
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


