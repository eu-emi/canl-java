/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.trust;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;
import java.util.Timer;

import eu.emi.security.authn.x509.StoreUpdateListener;

/**
 * Implementation of the {@link TrustAnchorStore} which uses JDK's {@link KeyStore}
 * as a in-memory storage.
 * @author K. Benedyczak
 */
public class JDKInMemoryTrustAnchorStore extends TrustAnchorStoreBase
{
	protected KeyStore keystore;
	protected Set<TrustAnchor> anchors;
	protected X509Certificate[] ca;
	
	public JDKInMemoryTrustAnchorStore(KeyStore ks) throws KeyStoreException
	{
		this(ks, null, -1, null);
	}

	protected JDKInMemoryTrustAnchorStore(KeyStore ks, Timer timer, 
			long updateInterval, 
			Collection<? extends StoreUpdateListener> listeners) 
					throws KeyStoreException
	{
		super(timer, updateInterval, listeners);
		this.keystore = ks;
		anchors = new HashSet<TrustAnchor>();
		load();
	}
	
	protected void load() throws KeyStoreException
	{
		Enumeration<String> aliases = keystore.aliases();
		anchors.clear();
		while (aliases.hasMoreElements())
		{
			String alias = aliases.nextElement();
			X509Certificate x509Cert = null;
			if (keystore.isCertificateEntry(alias))
			{
				Certificate cert = keystore.getCertificate(alias);
				if (!(cert instanceof X509Certificate))
					continue;
				x509Cert = (X509Certificate) cert;
			} else if (keystore.isKeyEntry(alias))
			{
				//This is bit ugly: we treat the user's certificate from the key entry
				//as trusted. This is the same behaviour as this implemented internally in JDK.
				Certificate[] certs = keystore.getCertificateChain(alias);
				if (!(certs[0] instanceof X509Certificate))
					continue;
				x509Cert = (X509Certificate) certs[0];
			} else
			{
				continue; //shouldn't never happen
			}

			checkValidity("Unknown location (certificate retrieved from keystore)", 
				x509Cert, true);
			anchors.add(new TrustAnchor(x509Cert, null));
		}
		ca = new X509Certificate[anchors.size()];
		int i=0;
		for (TrustAnchor anchor: anchors)
			ca[i++] = anchor.getTrustedCert();
	}
	
	
	@Override
	public Set<TrustAnchor> getTrustAnchors()
	{
		Set<TrustAnchor> ret = new HashSet<TrustAnchor>();
		ret.addAll(anchors);
		return ret;
	}

	@Override
	public X509Certificate[] getTrustedCertificates()
	{
		return Arrays.copyOf(ca, ca.length);
	}
	
	public KeyStore getKeyStore()
	{
		return keystore;
	}

	@Override
	protected void update()
	{
		//This implementation doesn't support updates
	}
}
