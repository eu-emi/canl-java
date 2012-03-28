/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.trust;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Collection;
import java.util.Timer;

import eu.emi.security.authn.x509.StoreUpdateListener;
import eu.emi.security.authn.x509.StoreUpdateListener.Severity;
import eu.emi.security.authn.x509.helpers.KeyStoreHelper;

/**
 * Implementation of the {@link TrustAnchorStore} which load JDK's {@link KeyStore}
 * from a file.
 * 
 * @author K. Benedyczak
 */
public class JDKFSTrustAnchorStore extends JDKInMemoryTrustAnchorStore
{
	private final String truststorePath;
	private transient final char[] password;
	private final String type;
	
	public JDKFSTrustAnchorStore(String truststorePath, char[] password, 
			String type, Timer t, long updateInterval,
			Collection<? extends StoreUpdateListener> listeners) throws KeyStoreException, IOException
	{
		super(readKeyStore(truststorePath, password, type), t, updateInterval, listeners);
		this.truststorePath = truststorePath;
		this.type = type;
		this.password = password;
		update();
	}
	
	private static KeyStore readKeyStore(String truststorePath, char[] password, 
			String type) throws IOException, KeyStoreException
	{
		InputStream is = new BufferedInputStream(new FileInputStream(truststorePath));
		KeyStore ks = KeyStoreHelper.getInstance(type);
		try
		{
			ks.load(is, password);
		} catch (NoSuchAlgorithmException e)
		{
			throw new KeyStoreException("Unsupported keystore integrity algorithm, " +
					"keystore path: " + truststorePath, e);
		} catch (CertificateException e)
		{
			throw new KeyStoreException("Some of the certificates found in the " +
					"keystore can not be loaded, keystore path: " 
					+ truststorePath, e);
		} finally
		{
			is.close();
		}
		return ks;
	}
	
	@Override
	protected void update()
	{
		KeyStore ks;
		try
		{
			ks = readKeyStore(truststorePath, password, type);
			keystore = ks;
			load();
			notifyObservers(truststorePath, StoreUpdateListener.CA_CERT,
					Severity.NOTIFICATION, null);
		} catch (Exception e)
		{
			notifyObservers(truststorePath, StoreUpdateListener.CA_CERT,
					Severity.ERROR, e);
		}
	}
	
	public String getTruststorePath()
	{
		return truststorePath;
	}
}
