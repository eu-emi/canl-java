/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.ns;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Collections;

import org.junit.Assert;

import org.apache.commons.io.FileUtils;
import org.junit.Test;

import eu.emi.security.authn.x509.NamespaceCheckingMode;
import eu.emi.security.authn.x509.ProxySupport;
import eu.emi.security.authn.x509.RevocationParameters;
import eu.emi.security.authn.x509.StoreUpdateListener;
import eu.emi.security.authn.x509.ValidationResult;
import eu.emi.security.authn.x509.impl.CertificateUtils;
import eu.emi.security.authn.x509.impl.CertificateUtils.Encoding;
import eu.emi.security.authn.x509.impl.OpensslCertChainValidator;
import eu.emi.security.authn.x509.impl.ValidatorParams;

/**
 * Integration test using {@link OpensslCertChainValidator} and testing (mostly) whether its 
 * namespace handling is working properly.
 * @author K. Benedyczak
 */
public class OpensslDirTest
{
	private static final int DELAY = 100;
	private static final String PMA_NS_ACCEPTING = 
			"TO Issuer \"/C=EU/O=EMITest/CN=The root CA1\" " +
			"PERMIT Subject \"/C=EU/O=EMITest/CN=.*\"";
	private static final String PMA_NS_REJECTING = 
			"TO Issuer \"/C=EU/O=EMITest/CN=The root CA1\" " +
			"PERMIT Subject \"/C=EU/O=EMINest/CN=.*\"";
	private static final String GLOBUS_NS_ACCEPTING = 
			"access_id_CA X509 '/C=EU/O=EMITest/CN=The root CA1'\n"+
			"pos_rights globus CA:sign\n" +
			"cond_subjects globus '\"/C=EU/O=EMITest/CN=*\"'";
	private static final String GLOBUS_NS_REJECTING = 
			"access_id_CA X509 '/C=EU/O=EMITest/CN=The root CA1'\n"+
			"pos_rights globus CA:sign\n" +
			"cond_subjects globus '\"/C=EU/O=EMITest/CN=Zuser*\"'";
	private File nsFile;
	private File spFile;
	private int test=0;
	private volatile int[] notCounter = new int[10];
	
	@Test
	public void test() throws Exception
	{
		File dir = initDir();
		nsFile = new File(dir, "77ab7b18.namespaces");
		spFile = new File(dir, "77ab7b18.signing_policy");
		
		X509Certificate cert = CertificateUtils.loadCertificate(
				new FileInputStream("src/test/testCAs/ca-simple/CA-issued/user1/newcert.pem"),
				Encoding.PEM);
		OpensslCertChainValidator validators[] = new OpensslCertChainValidator[] {
				new OpensslCertChainValidator(dir.toString(), false, NamespaceCheckingMode.IGNORE, DELAY, 
					new ValidatorParams(RevocationParameters.IGNORE, ProxySupport.ALLOW), false),
					
				new OpensslCertChainValidator(dir.toString(), false, NamespaceCheckingMode.EUGRIDPMA, DELAY, 
					new ValidatorParams(RevocationParameters.IGNORE, ProxySupport.ALLOW, Collections.singletonList(new MyListener(0))), false),

				new OpensslCertChainValidator(dir.toString(), false, NamespaceCheckingMode.EUGRIDPMA_AND_GLOBUS, DELAY, 
					new ValidatorParams(RevocationParameters.IGNORE, ProxySupport.ALLOW, Collections.singletonList(new MyListener(1))), false),
				
				new OpensslCertChainValidator(dir.toString(), false, NamespaceCheckingMode.EUGRIDPMA_AND_GLOBUS_REQUIRE, DELAY, 
					new ValidatorParams(RevocationParameters.IGNORE, ProxySupport.ALLOW, Collections.singletonList(new MyListener(2))), false),
				
				new OpensslCertChainValidator(dir.toString(), false, NamespaceCheckingMode.EUGRIDPMA_GLOBUS, DELAY, 
					new ValidatorParams(RevocationParameters.IGNORE, ProxySupport.ALLOW, Collections.singletonList(new MyListener(3))), false),
				
				new OpensslCertChainValidator(dir.toString(), false, NamespaceCheckingMode.EUGRIDPMA_GLOBUS_REQUIRE, DELAY, 
					new ValidatorParams(RevocationParameters.IGNORE, ProxySupport.ALLOW, Collections.singletonList(new MyListener(4))), false),
				
				new OpensslCertChainValidator(dir.toString(), false, NamespaceCheckingMode.EUGRIDPMA_REQUIRE, DELAY, 
					new ValidatorParams(RevocationParameters.IGNORE, ProxySupport.ALLOW, Collections.singletonList(new MyListener(5))), false),
				
				new OpensslCertChainValidator(dir.toString(), false, NamespaceCheckingMode.GLOBUS, DELAY, 
					new ValidatorParams(RevocationParameters.IGNORE, ProxySupport.ALLOW, Collections.singletonList(new MyListener(6))), false),
				
				new OpensslCertChainValidator(dir.toString(), false, NamespaceCheckingMode.GLOBUS_EUGRIDPMA, DELAY, 
					new ValidatorParams(RevocationParameters.IGNORE, ProxySupport.ALLOW, Collections.singletonList(new MyListener(7))), false),
				
				new OpensslCertChainValidator(dir.toString(), false, NamespaceCheckingMode.GLOBUS_EUGRIDPMA_REQUIRE, DELAY, 
					new ValidatorParams(RevocationParameters.IGNORE, ProxySupport.ALLOW, Collections.singletonList(new MyListener(8))), false),
				
				new OpensslCertChainValidator(dir.toString(), false, NamespaceCheckingMode.GLOBUS_REQUIRE, DELAY, 
					new ValidatorParams(RevocationParameters.IGNORE, ProxySupport.ALLOW, Collections.singletonList(new MyListener(9))), false),
				};

		//case: no ns declarations. 
		// All with require should fail, the rest succeed.
		boolean []results = new boolean[] {
				true, true, true, 
				false, true, false,
				false, true, true,
				false, false
		};
		check(cert, validators, results);
		

		
		//case: only EUGRIDPMA is present and is accepting. 
		// All should accept except  GLOBUS_REQUIRE
		results = new boolean[] {
				true, true, true, 
				true, true, true,
				true, true, true,
				true, false
		};
		updateAndWait(null, PMA_NS_ACCEPTING);
		check(cert, validators, results);
		

		//case: only GLOBUS is present and is accepting. 
		// All should accept except  EUGRIDPMA_REQUIRE
		results = new boolean[] {
				true, true, true, 
				true, true, true,
				false, true, true,
				true, true
		};
		updateAndWait(GLOBUS_NS_ACCEPTING, null);
		check(cert, validators, results);


		//case: only EUGRIDPMA is present and is rejecting. 
		// All having EUGRIDPMA enabled should fail, and GL_REQ too
		results = new boolean[] {
				true, false, false, 
				false, false, false,
				false, true, false,
				false, false
		};
		updateAndWait(null, PMA_NS_REJECTING);
		check(cert, validators, results);

		
		//case: only GLOBUS is present and is rejecting. 
		// All having GLOBUS enabled should fail, and EU_REQ too
		results = new boolean[] {
				true, true, false, 
				false, false, false,
				false, false, false,
				false, false
		};
		updateAndWait(GLOBUS_NS_REJECTING, null);
		check(cert, validators, results);

		
		//case6: GLOBUS is rejecting EU is accepting. 
		// All having GLOBUS first should fail, all with AND too, the rest pass
		results = new boolean[] {
				true, true, false, 
				false, true, true,
				true, false, false,
				false, false
		};
		updateAndWait(GLOBUS_NS_REJECTING, PMA_NS_ACCEPTING);
		check(cert, validators, results);

		
		//case7: GLOBUS accepting EU is rejecting. 
		// All having EU first should fail, all with AND too, the rest pass
		results = new boolean[] {
				true, false, false, 
				false, false, false,
				false, true, true,
				true, true
		};
		updateAndWait(GLOBUS_NS_ACCEPTING, PMA_NS_REJECTING);
		check(cert, validators, results);

		
		//case: both are accepting 
		// All should pass
		results = new boolean[] {
				true, true, true, 
				true, true, true,
				true, true, true,
				true, true
		};
		updateAndWait(GLOBUS_NS_ACCEPTING, PMA_NS_ACCEPTING);
		check(cert, validators, results);
		
		
		//case: both are rejecting 
		// only ignore should pass
		results = new boolean[] {
				true, false, false, 
				false, false, false,
				false, false, false,
				false, false
		};
		updateAndWait(GLOBUS_NS_REJECTING, PMA_NS_REJECTING);
		check(cert, validators, results);

		
		for (OpensslCertChainValidator v: validators)
			v.dispose();
	}
	
	private synchronized void incCounter(int n)
	{
		notCounter[n]++;
	}
	
	private void updateAndWait(String globus, String eu) throws IOException, InterruptedException
	{
		boolean[] withGlobus = {false, true, true, true, true, false, true, true, true, true};
		boolean[] withEu = {true, true, true, true, true, true, false, true, true, false};
		synchronized (this)
		{
			for (int i=0; i<10; i++)
				notCounter[i] = 0;
			if (globus != null)
				FileUtils.writeStringToFile(spFile, globus);
			if (eu != null)
				FileUtils.writeStringToFile(nsFile, eu);
			
			for (int i=0; i<10; i++)
			{
				int possible = 0;
				if (withGlobus[i] && globus != null)
					possible++;
				if (withEu[i] && eu != null)
					possible++;
				if (notCounter[i] < possible)
				{
					wait(50);
					i--;
				}
			}
		}
		Thread.sleep(100); 	//overkill to be 100% sure: we got notification about all policies being successfully 
					//reread, but those needs to be also updated (100ms for calling two setters ;-)
	}
	
	private void check(X509Certificate cert, OpensslCertChainValidator validators[], boolean []results)
	{
		System.out.println("------\nTEST " + ++test + "\n");
		for (int i=0; i<validators.length; i++)
		{
			OpensslCertChainValidator v = validators[i];
			ValidationResult res = v.validate(new X509Certificate[] {cert});
			System.out.println(i + ") got result: " + res);
			Assert.assertEquals("Error at position " + i, results[i], res.isValid());
		}
		nsFile.delete();
		spFile.delete();
	}

	private static File initDir() throws IOException
	{
		File dir = new File("target/test-tmp/openssl-nsTest");
		FileUtils.deleteDirectory(dir);
		dir.mkdirs();
		File caFile = new File("src/test/testCAs/ca-simple/CA-files/cacert.pem");
		File destFile = new File(dir, "77ab7b18.0");
		FileUtils.copyFile(caFile, destFile);
		return dir;
	}
	
	private class MyListener implements StoreUpdateListener
	{
		int number;
		
		public MyListener(int n)
		{
			number = n;
		}
		
		@Override
		public void loadingNotification(String location, String type,
				Severity level, Exception cause)
		{
			if (!type.equals(StoreUpdateListener.EACL_NAMESPACE) && 
					!type.equals(StoreUpdateListener.EUGRIDPMA_NAMESPACE))
				return;
			
			if (level != Severity.NOTIFICATION)
				System.err.println(type + " loading probelm: " + 
						location + " " + cause);
			else
				incCounter(number);
		}
	}
}
