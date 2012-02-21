/*
 * Copyright (c) 2011 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.impl;

import java.io.FileReader;
import java.io.IOException;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;

import javax.net.ssl.SSLHandshakeException;

import junit.framework.Assert;

import org.junit.Test;

import eu.emi.security.authn.x509.X509CertChainValidator;
import eu.emi.security.authn.x509.X509Credential;
import eu.emi.security.authn.x509.helpers.BinaryCertChainValidator;

/**
 * @author K. Benedyczak
 */
public class TestSSLHelpers
{
	private volatile Exception exc;
	private volatile int val;
	
	@Test
	public void testCreation() throws Exception
	{
		testCreation(true);
		testCreation(false);
	}

	private synchronized void setException(Exception e)
	{
		this.exc = e;
	}

	private synchronized void setVal(int val)
	{
		this.val = val;
	}
	
	private synchronized Exception getException()
	{
		return exc;
	}

	private synchronized int getVal()
	{
		return val;
	}
	
	
	public void testCreation(boolean mode) throws Exception
	{
		X509Credential c = new PEMCredential(new FileReader(CertificateUtilsTest.PFX + "pk-1.pem"), 
				new FileReader(CertificateUtilsTest.PFX + "cert-1.pem"),
				CertificateUtilsTest.KS_P);
		X509CertChainValidator v = new BinaryCertChainValidator(mode);
		final ServerSocket ss = SocketFactoryCreator.getServerSocketFactory(c, v).createServerSocket();
		ss.bind(null);
		
		Socket s = SocketFactoryCreator.getSocketFactory(c, v).createSocket();
		exc = null;
		val = -1;
		Runnable r1 = new Runnable()
		{
			@Override
			public void run()
			{
				try
				{
					Socket s = ss.accept();
					setVal(s.getInputStream().read());
					synchronized(this)
					{
						notifyAll();
					}
					ss.close();
				} catch (IOException e)
				{
					setException(e);
					synchronized(this)
					{
						notifyAll();
					}
				}
			}
		};
		Thread t1 = new Thread(r1);
		t1.start();
		
		if (mode)
		{
			s.connect(ss.getLocalSocketAddress());
			OutputStream os = s.getOutputStream();
			byte value = 12;
			synchronized(r1)
			{
				os.write(value);
				os.flush();
				r1.wait();
			}
			s.close();
			Assert.assertTrue(getException() == null);
			Assert.assertEquals(value, getVal());
		} else
		{
			s.connect(ss.getLocalSocketAddress());
			OutputStream os = s.getOutputStream();
			byte value = 12;
			try
			{
				os.write(value);
				Assert.fail("Was able to send message on invalid SSL channel");
			} catch (SSLHandshakeException e)
			{
				//OK
			}
		}
	}
}
