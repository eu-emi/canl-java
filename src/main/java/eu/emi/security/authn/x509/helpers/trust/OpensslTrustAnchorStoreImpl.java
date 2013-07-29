/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.trust;

import java.io.File;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Timer;

import eu.emi.security.authn.x509.StoreUpdateListener;
import eu.emi.security.authn.x509.StoreUpdateListener.Severity;
import eu.emi.security.authn.x509.helpers.ObserversHandler;
import eu.emi.security.authn.x509.helpers.ns.EuGridPmaNamespacesStore;
import eu.emi.security.authn.x509.helpers.ns.GlobusNamespacesStore;
import eu.emi.security.authn.x509.helpers.ns.NamespacesStore;
import eu.emi.security.authn.x509.impl.CertificateUtils.Encoding;

/**
 * Implementation of the truststore which uses CA certificates from a single directory 
 * in OpenSSL format. Each certificate should be stored in a file named HASH.NUM,
 * where HASH is an 8 digit hex number. The NUM must be a number, starting from 0.
 * The hash can be either of openssl pre 1.0.0 version 
 * (with 8 least significant digits of the MD5 hash of the certificate subject in DER format)
 * or in openssl 1.0.0 and above format (SHA1 hash of specially normalized DN). The class is configured
 * to use one or another, never both.
 * <p>
 * This class is extending the {@link DirectoryTrustAnchorStore} and restricts 
 * the certificates which are loaded.
 * 
 * @author K. Benedyczak
 */
public class OpensslTrustAnchorStoreImpl extends DirectoryTrustAnchorStore implements OpensslTrustAnchorStore
{
	public static final String CERT_WILDCARD = "????????.*";
	private boolean loadEuGridPmaNs;
	private boolean loadGlobusNs;
	private boolean openssl1Mode;
	private NamespacesStore pmaNsStore;
	private NamespacesStore globusNsStore;
	
	public OpensslTrustAnchorStoreImpl(String basePath,	Timer t, long updateInterval, boolean loadGlobusNs,
			boolean loadEuGridPmaNs, ObserversHandler observers, boolean openssl1Mode)
	{
		super(Collections.singletonList(basePath+File.separator+CERT_WILDCARD), 
				null, 0, t, updateInterval, Encoding.PEM, observers, true);
		this.openssl1Mode = openssl1Mode;
		pmaNsStore = new EuGridPmaNamespacesStore(observers, openssl1Mode);
		globusNsStore = new GlobusNamespacesStore(observers, openssl1Mode);
		this.loadEuGridPmaNs = loadEuGridPmaNs;
		this.loadGlobusNs = loadGlobusNs;
		update();
		scheduleUpdate();
	}
	
	/**
	 * For all URLs tries to load a CA cert and namespaces
	 */
	@Override
	protected void reloadCerts(Collection<URL> locations)
	{
		List<String> correctLocations = new ArrayList<String>();
		Set<TrustAnchorExt> tmpAnchors = new HashSet<TrustAnchorExt>();
		Map<URL, TrustAnchorExt> tmpLoc2anch = new HashMap<URL, TrustAnchorExt>();
		
		for (URL location: locations)
		{
			boolean loaded = tryLoadCert(location, tmpAnchors, tmpLoc2anch);
			if (loaded)
				correctLocations.add(location.getPath());
		}
		
		synchronized(this)
		{
			anchors.addAll(tmpAnchors);
			locations2anchors.putAll(tmpLoc2anch);
			if (loadEuGridPmaNs)
				pmaNsStore.setPolicies(correctLocations);
			if (loadGlobusNs)
				globusNsStore.setPolicies(correctLocations);
		}
	}
	
	protected boolean tryLoadCert(URL location, Set<TrustAnchorExt> tmpAnchors, Map<URL, TrustAnchorExt> tmpLoc2anch)
	{
		String fileHash = OpensslTruststoreHelper.getFileHash(location.getPath(), 
				OpensslTruststoreHelper.CERT_REGEXP);
		if (fileHash == null)
			return false;

		X509Certificate cert;
		try
		{
			cert = loadCert(location);
		} catch (Exception e)
		{
			observers.notifyObservers(location.toExternalForm(), StoreUpdateListener.CA_CERT,
					Severity.ERROR, e);
			return false;
		}

		String certHash = OpensslTruststoreHelper.getOpenSSLCAHash(cert.getSubjectX500Principal(), openssl1Mode);
		if (!fileHash.equalsIgnoreCase(certHash))
			return false;

		TrustAnchorExt anchor = new TrustAnchorExt(cert, null);
		tmpAnchors.add(anchor);
		tmpLoc2anch.put(location, anchor);
		return true;
	}
	
	@Override
	public NamespacesStore getPmaNsStore()
	{
		return pmaNsStore;
	}

	@Override
	public NamespacesStore getGlobusNsStore()
	{
		return globusNsStore;
	}
}


