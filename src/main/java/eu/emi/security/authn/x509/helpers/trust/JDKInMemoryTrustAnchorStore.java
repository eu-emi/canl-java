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

import eu.emi.security.authn.x509.UpdateErrorListener;

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
			Collection<? extends UpdateErrorListener> listeners) 
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
			if (keystore.isCertificateEntry(alias))
			{
				Certificate cert = keystore.getCertificate(alias);
				if (!(cert instanceof X509Certificate))
					continue;
				anchors.add(new TrustAnchor((X509Certificate) cert, null));
			}
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
