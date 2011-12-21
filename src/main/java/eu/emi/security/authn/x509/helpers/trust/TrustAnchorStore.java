/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.trust;

import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Set;

import eu.emi.security.authn.x509.StoreUpdateListener;

/**
 * Implementations provide trust store material: a list of trusted CA certificates. 
 * @author K. Benedyczak
 */
public interface TrustAnchorStore
{
	public Set<TrustAnchor> getTrustAnchors();
	public X509Certificate[] getTrustedCertificates();
	public void addUpdateListener(StoreUpdateListener listener);
	public void removeUpdateListener(StoreUpdateListener listener);
	public void dispose();
}
