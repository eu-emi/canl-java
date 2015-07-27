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
import java.security.InvalidAlgorithmParameterException;
import java.security.cert.CRLException;
import java.security.cert.CRLSelector;
import java.security.cert.X509CRL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.WeakHashMap;

import javax.security.auth.x500.X500Principal;

import eu.emi.security.authn.x509.StoreUpdateListener.Severity;
import eu.emi.security.authn.x509.helpers.CachedElement;
import eu.emi.security.authn.x509.helpers.ObserversHandler;
import eu.emi.security.authn.x509.helpers.trust.OpensslTruststoreHelper;
import eu.emi.security.authn.x509.impl.CRLParameters;
import eu.emi.security.authn.x509.impl.X500NameUtils;



/**
 * Handles an Openssl-like CRL store. CRLs are loaded on demand from disk and cached in memory,
 * for no longer then updateInterval parameter.
 * <p>
 * This class is thread safe.
 * </p> 
 *    
 * @author K. Benedyczak
 */
public class LazyOpensslCRLStoreSpi extends AbstractCRLStoreSPI
{
	private static final String SUFFIX = "\\.r[0-9]+";
	//constant state
	private final File directory;
	private final boolean openssl1Mode;
	
	//variable state
	private Map<String, CachedElement<List<X509CRL>>> cachedCRLsByHash;

	/**
	 * Creates a new CRL store.
	 * @param path path
	 * @param crlUpdateInterval crl update interval
	 * @param observers observers handler
	 * @param openssl1Mode openssl 1 mode
	 * @throws InvalidAlgorithmParameterException invalid algorithm parameter exception
	 */
	public LazyOpensslCRLStoreSpi(String path, long crlUpdateInterval, ObserversHandler observers,
			boolean openssl1Mode) throws InvalidAlgorithmParameterException
	{
		super(new CRLParameters(Collections.singletonList(path),
				crlUpdateInterval, 0, null), observers);
		this.directory = new File(path);
		this.openssl1Mode = openssl1Mode;
		cachedCRLsByHash = new WeakHashMap<String, CachedElement<List<X509CRL>>>();
	}

	protected X509CRL loadCRL(File file) throws IOException, CRLException, URISyntaxException
	{
		InputStream is = new BufferedInputStream(new FileInputStream(file));
		try
		{
			X509CRL ret = (X509CRL)factory.generateCRL(is);
			if (ret == null)
				throw new CRLException("Unknown problem when parsing/loading the CRL");
			return ret;
		} finally
		{
			is.close();
		}
	}
	
	@Override
	public synchronized void setUpdateInterval(long newInterval)
	{
		this.updateInterval = newInterval;
	}

	public synchronized long getUpdateInterval()
	{
		return updateInterval;
	}
	
	@Override
	public void dispose()
	{
	}
	
	protected X509CRL reloadCRL(File location)
	{
		X509CRL crl;
		try
		{
			crl = loadCRL(location);
			notifyObservers(location.getAbsolutePath(), Severity.NOTIFICATION, null);
		} catch (Exception e)
		{
			notifyObservers(location.getAbsolutePath(), Severity.ERROR, e);
			return null;
		}
		return crl;
	}
	
	private Collection<X509CRL> filterByIssuer(X500Principal issuer, Collection<X509CRL> all)
	{
		List<X509CRL> ret = new ArrayList<X509CRL>(all.size());
		for (X509CRL crl: all)
			if (X500NameUtils.rfc3280Equal(issuer, crl.getIssuerX500Principal()))
				ret.add(crl);
		return ret;
	}
	
	@Override
	protected synchronized Collection<X509CRL> getCRLForIssuer(X500Principal issuer)
	{
		String issuerHash = OpensslTruststoreHelper.getOpenSSLCAHash(issuer, openssl1Mode);
		CachedElement<List<X509CRL>> cached = cachedCRLsByHash.get(issuerHash);
		if (cached != null && !cached.isExpired(updateInterval))
		{
			return filterByIssuer(issuer, cached.getElement());
		}
		
		Collection<File> crls = OpensslTruststoreHelper.getFilesWithRegexp(issuerHash+SUFFIX, directory); 
		
		List<X509CRL> ret = new ArrayList<X509CRL>(crls.size());
		for (File location: crls)
		{
			X509CRL crl = reloadCRL(location);
			if (crl != null)
				ret.add(crl);
		}
		
		cachedCRLsByHash.put(issuerHash, new CachedElement<List<X509CRL>>(ret));
		return filterByIssuer(issuer, ret);
	}

	@Override
	protected synchronized Collection<X509CRL> getCRLWithMatcher(CRLSelector selectorRaw)
	{
		Collection<File> crls = OpensslTruststoreHelper.getFilesWithRegexp(".*" + SUFFIX, directory); 
		List<X509CRL> ret = new ArrayList<X509CRL>();
		for (File location: crls)
		{
			X509CRL crl = reloadCRL(location);
			if (crl != null && selectorRaw.match(crl))
				ret.add(crl);
		}
		return ret;
	}

}



