/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.impl;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.security.cert.CRL;
import java.security.cert.CertStoreSpi;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLSelector;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Timer;

import static org.junit.Assert.*;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.util.encoders.Base64;
import org.junit.Test;

import eu.emi.security.authn.x509.UpdateErrorListener;
import eu.emi.security.authn.x509.helpers.crl.CRLParameters;
import eu.emi.security.authn.x509.helpers.crl.OpensslCRLStoreSpi;
import eu.emi.security.authn.x509.helpers.crl.PlainCRLStoreSpi;
import eu.emi.security.authn.x509.helpers.trust.OpensslTrustAnchorStore;

public class CRLTest
{
	private int notificationOK;
	private int localPort;
	private int opensslWarn, opensslErr;
	
	
	private static File initDir() throws IOException
	{
		File dir = new File("target/test-tmp/crls/diskCache");
		FileUtils.deleteDirectory(dir);
		dir.mkdirs();
		return dir;
	}
	
	@Test
	public void testUpdateCleanup() throws Exception
	{
		File dir = initDir();
		
		Timer t = new Timer();
		List<String> crls = new ArrayList<String>();
		String crlURL1 = dir.getPath() + "/*.in";
		crls.add(crlURL1);
		File target = new File(dir, "file.in");
		FileUtils.copyFile(new File("src/test/resources/test-pems/crls/relaxationsubca.crl"), 
				target);
		
		CRLParameters params = new CRLParameters(crls, 250, 
				5000, dir.getPath());
		PlainCRLStoreSpi store = new PlainCRLStoreSpi(params, t, 
				new ArrayList<UpdateErrorListener>(0));

		checkCRL("CN=the subca CA,OU=Relaxation,O=Utopia,L=Tropic,C=UG", store, 1);
		target.delete();
		Thread.sleep(500);
		checkCRL("CN=the subca CA,OU=Relaxation,O=Utopia,L=Tropic,C=UG", store, 0);
		
		store.dispose();
	}	
	
	
	@Test
	public void testNotificationsAndUpdate() throws Exception
	{
		File dir = initDir();
		
		Timer t = new Timer();
		List<String> crls = new ArrayList<String>();
		final String crlURL1 = "http://127.0.0.1/non-existing/crl.pem";
		final String crlURL2 = "http://127.0.0.1/non-existing2/crl2.pem";
		crls.add(crlURL1);
		crls.add(crlURL2);
		String base64URL = new String(Base64.encode(crlURL1.getBytes())) + "-crl.der";
		FileUtils.copyFile(new File("src/test/resources/test-pems/crls/relaxationsubca.crl"), 
				new File(dir, base64URL));
		
		CRLParameters params = new CRLParameters(crls, 500, 
				100, dir.getPath());
		notificationOK=0;
		UpdateErrorListener listener = new UpdateErrorListener()
		{
			public void loadingProblem(String crlLocation, String type, 
					Severity level,
					Exception cause)
			{
				assertEquals(type, UpdateErrorListener.CRL);
				if (level.equals(Severity.ERROR))
				{
					assertEquals(crlURL2, crlLocation);
					assertTrue(cause instanceof IOException);
					notificationOK++;
				} else
				{
					assertEquals(crlURL1, crlLocation);
					assertTrue(cause instanceof IOException);
					assertTrue(cause.getMessage().contains("cached copy"));
					notificationOK++;
				}
			}
		};
		
		PlainCRLStoreSpi store = new PlainCRLStoreSpi(params, t, 
				Collections.singleton(listener));
		assertEquals(2, notificationOK);
		store.removeUpdateErrorListener(listener);
		store.addUpdateErrorListener(listener);
		Thread.sleep(750);
		assertEquals(4, notificationOK);
		store.setUpdateInterval(-1);
		Thread.sleep(750);
		assertEquals(4, notificationOK);
		store.dispose();
	}
	
	@Test
	public void testTimeout() throws Exception
	{
		Thread server = new Thread()
		{
			public void run()
			{
				try
				{
					ServerSocket ss = new ServerSocket(0, 0,
							InetAddress.getByName("127.0.0.1"));
					localPort = ss.getLocalPort();
					Socket s = ss.accept();
					System.out.println("Got connection");
					Thread.sleep(5000);
					s.close();
					ss.close();
				} catch (Exception e)
				{
					fail(e.toString());
				}
			}
		};
		server.start();
		Thread.sleep(250);
		
		File dir = initDir();
		
		Timer t = new Timer();
		List<String> crls = new ArrayList<String>();
		final String crlURL1 = "http://127.0.0.1:"+ localPort + "/crl.pem";
		crls.add(crlURL1);
		CRLParameters params = new CRLParameters(crls, -1, 500, dir.getPath());
		notificationOK=0;
		UpdateErrorListener listener = new UpdateErrorListener()
		{
			public void loadingProblem(String crlLocation, String type, Severity level,
					Exception cause)
			{
				assertEquals(type, UpdateErrorListener.CRL);
				assertEquals(level, Severity.ERROR);
				assertEquals(crlURL1, crlLocation);
				assertTrue(cause instanceof SocketTimeoutException);
				System.out.println(crlLocation + " " + cause.toString());
				notificationOK++;
			}
		};
		long start = System.currentTimeMillis();
		PlainCRLStoreSpi store = new PlainCRLStoreSpi(params, t, Collections.singleton(listener));
		assertEquals(1, notificationOK);
		start = System.currentTimeMillis() - start;
		assertTrue(start < 500*3);
		store.dispose();
	}
	
	@Test
	public void testLoadPlain() throws Exception
	{
		File dir = initDir();
		
		Timer t = new Timer();
		List<String> crls = new ArrayList<String>();
		String crlURL1 = "http://www.man.poznan.pl/plgrid-ca/crl.pem";
		String crlURL2 = "http://127.0.0.1/non-existing/crl.pem";
		String crlURL3 = "src/test/resources/test-pems/crls/*.pem";
		crls.add(crlURL1);
		crls.add(crlURL2);
		crls.add(crlURL3);
		String base64URL1 = new String(Base64.encode(crlURL1.getBytes())) + "-crl.der";
		String base64URL2 = new String(Base64.encode(crlURL2.getBytes())) + "-crl.der";
		FileUtils.copyFile(new File("src/test/resources/test-pems/crls/relaxationsubca.crl"), 
				new File(dir, base64URL2));
		
		CRLParameters params = new CRLParameters(crls, -1, 
				5000, dir.getPath());
		PlainCRLStoreSpi store = new PlainCRLStoreSpi(params, t, 
				new ArrayList<UpdateErrorListener>(0));

		
		checkCRL("CN=Polish Grid CA,O=GRID,C=PL", store, 1);
		String[] ls = dir.list();
		assertTrue(ls.length == 2);
		assertTrue(ls[0].equals(base64URL1) || ls[1].equals(base64URL1));

		checkCRL("CN=the subca CA,OU=Relaxation,O=Utopia,L=Tropic,C=UG", store, 1);
		
		checkCRL("CN=the trusted CA,OU=Relaxation,O=Utopia,L=Tropic,C=UG", store, 1);
		
		checkCRL("CN=missing CA,C=UG", store, 0);
		
		assertEquals(crls, store.getLocations());
		store.dispose();
	}
	
	@Test
	public void testLoadOpenssl() throws Exception
	{
		Timer t = new Timer();
		opensslErr = 0;
		opensslWarn = 0;
		UpdateErrorListener listener = new UpdateErrorListener()
		{
			public void loadingProblem(String crlLocation, String type, Severity level,
					Exception cause)
			{
				assertEquals(type, UpdateErrorListener.CRL);
				if (level == Severity.ERROR)
					opensslErr++;
				else
					opensslWarn++;
			}
		};
		
		OpensslCRLStoreSpi store = new OpensslCRLStoreSpi(
				"src/test/resources/openssl-testcrldir", -1, t, 
				Collections.singleton(listener));

		
		checkCRL("CN=the trusted CA,OU=Relaxation,O=Utopia,L=Tropic,C=UG", store, 1);
		assertEquals(1, opensslErr);
		assertEquals(1, opensslWarn);
		
		store.dispose();
	}
	
	@Test
	public void checkPattern() throws Exception
	{
		assertNotNull(OpensslTrustAnchorStore.getFileHash(new URL("file:///5a1a2F89.r0"), 
				"^([0-9a-fA-F]{8})\\.r[\\d]+$"));
	}
	
	private static void checkCRL(String caDN, CertStoreSpi store, int expected) throws Exception
	{
		X509CRLSelector selector = new X509CRLSelector();
		selector.addIssuerName(caDN);
		Collection<? extends CRL> matched = store.engineGetCRLs(selector);
		assertEquals(expected, matched.size());
		if (expected > 0)
		{
			X509CRL crl = (X509CRL) matched.iterator().next();
			assertTrue(X500NameUtils.equal(crl.getIssuerX500Principal(), caDN));
		}
	}
}
