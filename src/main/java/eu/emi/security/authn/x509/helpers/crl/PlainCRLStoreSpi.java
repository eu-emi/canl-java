/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.crl;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLConnection;
import java.security.InvalidAlgorithmParameterException;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.CRLSelector;
import java.security.cert.CertSelector;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLSelector;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.Timer;
import java.util.TimerTask;

import javax.security.auth.x500.X500Principal;

import eu.emi.security.authn.x509.UpdateErrorListener;
import eu.emi.security.authn.x509.UpdateErrorListener.Severity;
import eu.emi.security.authn.x509.helpers.pkipath.PlainStoreUtils;



/**
 * Handles an in-memory CRL store.
 * <p>
 * CRLs may be provided as URLs or local files. If the CRL is provided as a local file
 * (i.e. is not an absolute URL) then it can contain wildcard characters ('*', '?'). 
 * In case of wildcard locations, the actual file list is regenerated on each update.
 * <p>
 * All CRLs are loaded and parsed to establish CA->CRL mapping. This mapping is updated
 * after the updateInterval time is passed.
 * <p>
 * Faulty CRL locations together with the respective errors can be obtained 
 * by using a listener.
 * <p>
 * It is possible to pass more then one location of CRLs of the same CA.
 * <p>
 * The class is implemented in an asynchronous mode: CRLs are updated on regular intervals
 * (or only once on startup). The CRL searching is independent of the updates and never blocks 
 * to download, read or parse a CRL. 
 * <p>
 * CRLs downloaded from a remote URL (http or ftp) can be cached on a local disk. If the update 
 * task can not download the CRL which was previously cached on disk, 
 * then the version from disk is returned. 
 * <p>
 * This class is thread safe.
 * </p> 
 *    
 * @author K. Benedyczak
 */
public class PlainCRLStoreSpi extends AbstractCRLCertStoreSpi
{
	//constant state
	private CRLParameters params;
	private final CertificateFactory factory;
	private final PlainStoreUtils utils;
	private Timer timer;
	
	//variable state
	private long updateInterval;
	private Object intervalLock = new Object();
	private Map<X500Principal, Set<URL>> ca2location;
	private Map<URL, X509CRL> loadedCRLs;

	
	public PlainCRLStoreSpi(CRLParameters params, Timer t, 
			Collection<? extends UpdateErrorListener> listeners) throws InvalidAlgorithmParameterException
	{
		super(params, listeners);
		this.params = params.clone();
		loadedCRLs = new HashMap<URL, X509CRL>();
		ca2location = new HashMap<X500Principal, Set<URL>>();
		
		utils = new PlainStoreUtils(this.params.getDiskCachePath(), "-crl", 
				this.params.getCrls());
		try
		{
			factory = CertificateFactory.getInstance("X.509");
		} catch (CertificateException e)
		{
			throw new RuntimeException("Can't find certificate fctory" +
					" for alg. X.509, JDK is misconfigured?", e);
		}
		updateInterval = this.params.getCrlUpdateInterval();
		timer = t;
		update();
		scheduleUpdate();
	}

	protected X509CRL loadCRL(URL url) throws IOException, CRLException, URISyntaxException
	{
		String protocol = url.getProtocol();
		boolean local = false;
		if (protocol.equalsIgnoreCase("file"))
			local = true;
		X509CRL ret;
		try
		{
			URLConnection conn = url.openConnection();
			if (!local)
			{
				conn.setConnectTimeout(params.getRemoteConnectionTimeout());
				conn.setReadTimeout(params.getRemoteConnectionTimeout());
			}
			InputStream is = new BufferedInputStream(conn.getInputStream());
			ret = (X509CRL)factory.generateCRL(is);
			is.close();
		} catch (IOException e)
		{
			if (!local && params.getDiskCachePath() != null)
			{
				File input = utils.getCacheFile(url);
				if (input.exists())
				{
					InputStream is = new BufferedInputStream(
							new FileInputStream(input));
					ret = (X509CRL)factory.generateCRL(is);
					is.close();
					notifyObservers(url.toExternalForm(), Severity.WARNING,
							new IOException("Warning: CRL was not loaded from its URL, " +
							"but its previously cached copy was loaded from disk file " + input.getPath(), e));
					return ret;
				} else
					throw e;
			}
			throw e;
		}
		
		if (!local)
			utils.saveCacheFile(ret.getEncoded(), url);
		
		return ret;
	}
	
	public List<String> getLocations()
	{
		return utils.getLocations();
	}
	
	public void setUpdateInterval(long newInterval)
	{
		synchronized (intervalLock)
		{
			long old = updateInterval;
			this.updateInterval = newInterval;
			if (old <= 0)
				scheduleUpdate();
		}
	}

	public long getUpdateInterval()
	{
		long ret;
		synchronized (intervalLock)
		{
			ret = updateInterval; 
		}
		return ret;
	}
	
	/**
	 * Removes those mappings which are for the not known locations.
	 * Happens when a file was removed from a wildcard listing.
	 */
	private synchronized void removeStaleIssuerMapping()
	{
		Iterator<Entry<X500Principal, Set<URL>>> itMain = ca2location.entrySet().iterator();
		while (itMain.hasNext())
		{
			Entry<X500Principal, Set<URL>> entry = itMain.next();
			Iterator<URL> it = entry.getValue().iterator();
			while (it.hasNext())
			{
				URL u = it.next();
				if (!utils.isPresent(u))
				{
					it.remove();
					loadedCRLs.remove(u);
				}
			}
		}
	}
	
	/**
	 * For all URLs tries to load a CRL
	 */
	protected void reloadCRLs(Collection<URL> locations)
	{
		for (URL location: locations)
		{
			X509CRL crl;
			try
			{
				crl = loadCRL(location);
			} catch (Exception e)
			{
				notifyObservers(location.toExternalForm(), Severity.ERROR, e);
				continue;
			}
			addCRL(crl, location);
		}
	}
	
	protected synchronized void addCRL(X509CRL crl, URL location)
	{
		Set<URL> set = ca2location.get(crl.getIssuerX500Principal());
		if (set == null)
		{
			set = new HashSet<URL>();
			ca2location.put(crl.getIssuerX500Principal(), set);
		}
		set.add(location);
		loadedCRLs.put(location, crl);
	}
	
	/**
	 * 1. work only if updateNeeded()
	 * 2. for all wildcards refresh file lists
	 * 3. remove the locations not valid anymore
	 * 4. for all location URLs try to get the CRL
	 * 5. update timestamp
	 * 6. schedule the next update if enabled
	 */
	private void update()
	{
		utils.establishWildcardsLocations();
		removeStaleIssuerMapping();
		reloadCRLs(utils.getURLLocations());
		reloadCRLs(utils.getResolvedWildcards());
	}
	
	private void scheduleUpdate()
	{
		if (getUpdateInterval() > 0)
			timer.schedule(new TimerTask()
			{
				public void run()
				{
					if (getUpdateInterval() > 0)
						update();
					scheduleUpdate();
				}
			}, getUpdateInterval());		
	}
	
	protected synchronized Collection<X509CRL> getCRLForIssuer(X500Principal issuer)
	{
		Set<URL> locations = ca2location.get(issuer);
		if (locations == null)
			return Collections.emptyList();
		List<X509CRL> ret = new ArrayList<X509CRL>(locations.size());
		for (URL location: locations)
			ret.add(loadedCRLs.get(location));
		return ret;
	}
	
	@Override
	public Collection<? extends Certificate> engineGetCertificates(
			CertSelector selector) throws CertStoreException
	{
		return Collections.emptySet();
	}

	@Override
	public Collection<? extends CRL> engineGetCRLs(CRLSelector selectorRaw)
			throws CertStoreException
	{
		if (!(selectorRaw instanceof X509CRLSelector))
			throw new IllegalArgumentException(getClass().getName() + 
					" class supports only X509CRLSelector, got: " 
					+ selectorRaw.getClass().getName());
		X509CRLSelector selector = (X509CRLSelector) selectorRaw;
		
		Collection<X500Principal> issuers = selector.getIssuers();
		List<X509CRL> ret = new ArrayList<X509CRL>();
		if (issuers == null)
			return ret;
		for (X500Principal issuer: issuers)
		{
			Collection<X509CRL> crls = getCRLForIssuer(issuer);
			for (X509CRL crl: crls)
				if (selector.match(crl))
					ret.add(crl);
		}
		return ret;
	}
	
	/**
	 * After calling this method no notification will be produced and subsequent
	 * updates won't be scheduled. However one next update may be run.
	 */
	public void dispose()
	{
		removeAllObservers();
		setUpdateInterval(-1);
	}
}



