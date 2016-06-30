/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.trust;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLConnection;
import java.security.cert.CertificateEncodingException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Timer;
import java.util.Map.Entry;

import eu.emi.security.authn.x509.StoreUpdateListener;
import eu.emi.security.authn.x509.StoreUpdateListener.Severity;
import eu.emi.security.authn.x509.helpers.ObserversHandler;
import eu.emi.security.authn.x509.helpers.pkipath.PlainStoreUtils;
import eu.emi.security.authn.x509.impl.CertificateUtils;
import eu.emi.security.authn.x509.impl.CertificateUtils.Encoding;

/**
 * Retrieves CA certificates from locations given as local paths with wildcards
 * or URLs.
 * @author K. Benedyczak
 */
public class DirectoryTrustAnchorStore extends TimedTrustAnchorStoreBase
{
	private final PlainStoreUtils utils;
	private final int connTimeout;
	private final String cacheDir;
	protected Set<TrustAnchorExt> anchors;
	protected Map<URL, TrustAnchorExt> locations2anchors;
	protected Encoding encoding;


	public DirectoryTrustAnchorStore(List<String> locations, String diskCache,
			int connectionTimeout, Timer t, long updateInterval, Encoding encoding,
			ObserversHandler listeners)
	{
		this(locations, diskCache, connectionTimeout, t, 
				updateInterval, encoding, listeners, false);
	}

	protected DirectoryTrustAnchorStore(List<String> locations, String diskCache,
			int connectionTimeout, Timer t, long updateInterval, Encoding encoding, 
			ObserversHandler observers, boolean noFirstUpdate)
	{
		super(t, updateInterval, observers);
		this.utils = new PlainStoreUtils(diskCache, "-cacert", locations);
		if (connectionTimeout < 0)
			throw new IllegalArgumentException("Remote connection timeout must be a non negative number");
		this.connTimeout = connectionTimeout;
		this.cacheDir = diskCache;
		anchors = new HashSet<TrustAnchorExt>();
		locations2anchors = new HashMap<URL, TrustAnchorExt>();
		this.encoding = encoding;
		if (!noFirstUpdate)
		{
			update();
			scheduleUpdate();
		}
	}

	protected X509Certificate[] loadCerts(URL url) throws IOException, URISyntaxException, CertificateEncodingException
	{
		String protocol = url.getProtocol();
		boolean local = false;
		if (protocol.equalsIgnoreCase("file"))
			local = true;
		X509Certificate[] ret;
		try
		{
			URLConnection conn = url.openConnection();
			if (!local)
			{
				conn.setConnectTimeout(connTimeout);
				conn.setReadTimeout(connTimeout);
			}
			InputStream is = new BufferedInputStream(conn.getInputStream());
			ret = CertificateUtils.loadCertificates(is, getEncoding());
			observers.notifyObservers(url.toExternalForm(),
					StoreUpdateListener.CA_CERT,
					Severity.NOTIFICATION, null);
		} catch (IOException e)
		{
			if (!local && cacheDir != null)
			{
				File input = utils.getCacheFile(url);
				if (input.exists())
				{
					InputStream is = new BufferedInputStream(
							new FileInputStream(input));
					ret = CertificateUtils.loadCertificates(is, getEncoding());
					is.close();
					observers.notifyObservers(url.toExternalForm(),
							StoreUpdateListener.CA_CERT,
							Severity.WARNING,
							new IOException("Warning: CA certificate was not loaded from its URL, " +
							"but its previous cached copy was loaded from disk file " + input.getPath(), e));
					return ret;
				} else
					throw e;
			}
			throw e;
		}
		
		if (!local && ret.length == 1)
			utils.saveCacheFile(ret[0].getEncoded(), url);
		
		return ret;
	}

	/**
	 * For all URLs tries to load a CA cert. Information for extensions:
	 * this method is guaranteed to be called once per update.
	 *
	 * @param locations a collection of URLs
	 */
	protected void reloadCerts(Collection<URL> locations)
	{
		Set<TrustAnchorExt> tmpAnchors = new HashSet<TrustAnchorExt>();
		Map<URL, TrustAnchorExt> tmpLoc2anch = new HashMap<URL, TrustAnchorExt>();
		for (URL location: locations)
		{
			X509Certificate[] certs;
			try
			{
				certs = loadCerts(location);
			} catch (Exception e)
			{
				observers.notifyObservers(location.toExternalForm(), 
						StoreUpdateListener.CA_CERT,
						Severity.ERROR, e);
				continue;
			}
			for (X509Certificate cert: certs)
			{
				checkValidity(location.toExternalForm(), cert, false);
				TrustAnchorExt anchor = new TrustAnchorExt(cert, null);
				tmpAnchors.add(anchor);
				tmpLoc2anch.put(location, anchor);
			}
		}
		synchronized(this)
		{
			anchors.addAll(tmpAnchors);
			locations2anchors.putAll(tmpLoc2anch);
		}
	}
	
	/**
	 * Removes those certs which are for the not known locations.
	 * Happens when a file was removed from a wildcard listing.
	 */
	private synchronized void removeStaleCas()
	{
		Iterator<Entry<URL, TrustAnchorExt>> itMain = locations2anchors.entrySet().iterator();
		while (itMain.hasNext())
		{
			Entry<URL, TrustAnchorExt> entry = itMain.next();
			if (!utils.isPresent(entry.getKey()))
			{
				anchors.remove(entry.getValue());
				itMain.remove();
			}
		}
	}
	
	/**
	 * 1. work only if schedulingNeeded()
	 * 2. for all wildcards refresh file lists
	 * 3. remove the locations not valid anymore
	 * 4. for all location URLs try to get the cert
	 * 5. update timestamp
	 * 6. schedule the next update if enabled
	 */
	protected void update()
	{
		utils.establishWildcardsLocations();
		removeStaleCas();
		List<URL> resolvedLocations = new ArrayList<URL>();
		resolvedLocations.addAll(utils.getURLLocations());
		resolvedLocations.addAll(utils.getResolvedWildcards());
		reloadCerts(resolvedLocations);
	}
	
	@Override
	public synchronized Set<TrustAnchor> getTrustAnchors()
	{
		Set<TrustAnchor> ret = new HashSet<TrustAnchor>();
		ret.addAll(anchors);
		return ret;
	}

	@Override
	public synchronized X509Certificate[] getTrustedCertificates()
	{
		X509Certificate[] ret = new X509Certificate[anchors.size()];
		int i=0;
		for (TrustAnchor ta: anchors)
			ret[i++] = ta.getTrustedCert();
		return ret;
	}
	
	public List<String> getLocations()
	{
		return utils.getLocations();
	}
	
	public int getConnTimeout()
	{
		return connTimeout;
	}

	public String getCacheDir()
	{
		return cacheDir;
	}
	
	public Encoding getEncoding()
	{
		return encoding;
	}
}
