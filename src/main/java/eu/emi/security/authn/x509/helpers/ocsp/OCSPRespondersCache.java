/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.ocsp;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.Map;

import eu.emi.security.authn.x509.OCSPParametes;


/**
 * OCSP failing responses cache: in memory with disk persistence. Only IOExceptions are cached.
 * 
 * @author K. Benedyczak
 */
public class OCSPRespondersCache extends OCSPCacheBase
{
	private Map<String, ResponderCacheEntry> respondersCache;
	
	/**
	 * 
	 * @param maxTtl maximum time after each cached response expires. Negative for no cache at all, 0 for no limit
	 * (i.e. caching time will be only controlled by the OCSP response validity period). In ms.
	 * @param diskPath if not null, cached responses will be stored on disk.
	 * @param prefix used if disk cache is enabled, as a common prefix for all files created in the cache directory. 
	 */
	public OCSPRespondersCache(long maxTtl, File diskPath, String prefix)
	{
		super(maxTtl == 0 ? OCSPParametes.DEFAULT_CACHE : maxTtl, diskPath, prefix);
		respondersCache = Collections.synchronizedMap(new BoundedSizeLruMap<String, ResponderCacheEntry>(100));
	}

	/**
	 * Checks if there is a cached and not outdated cache entry for a given responder key. If this is the case
	 * a cached exception is thrown.
	 * @param responderKey responder key
	 * @throws IOException IO exception
	 */
	public void checkCachedError(String responderKey) throws IOException
	{
		ResponderCacheEntry cachedError = respondersCache.get(responderKey);
		if (cachedError == null && diskPath != null)
		{
			File f = new File(diskPath, prefix + responderKey);
			if (f.exists())
				cachedError = loadResponderFromDisk(f);
		}
		if (cachedError == null)
			return;
		
		Date now = new Date();
		if (now.after(cachedError.maxValidity))
		{
			respondersCache.remove(responderKey);
			if (diskPath != null)
			{
				File f = new File(diskPath, prefix + responderKey);
				f.delete();
			}
			return;
		}
		
		if (cachedError.error != null)
			throw cachedError.error;
	}
	
	public void addToCache(String key, IOException error) throws IOException
	{
		Date maxCacheValidity = new Date(System.currentTimeMillis() + maxTtl);
		ResponderCacheEntry entry = new ResponderCacheEntry(maxCacheValidity, error); 
		respondersCache.put(key, entry);
		if (diskPath != null)
		{
			File f = new File(diskPath, prefix + key);
			storeResponderToDisk(f, entry);
		}
	}

	public void clearMemoryCache()
	{
		respondersCache.clear();
	}
	
	private void storeResponderToDisk(File f, ResponderCacheEntry entry) throws IOException
	{
		if (f.exists())
			f.delete();
		ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(f));
		try
		{
			oos.writeObject(entry.maxValidity);
			oos.writeObject(entry.error);
		} finally
		{
			oos.close();
		}
	}

	private ResponderCacheEntry loadResponderFromDisk(File f)
	{
		ObjectInputStream ois = null;
		try
		{
			ois = new ObjectInputStream(new FileInputStream(f));
			Date maxCache = (Date)ois.readObject();
			IOException error = (IOException) ois.readObject();
			return new ResponderCacheEntry(maxCache, error);
		} catch (Exception e)
		{
			f.delete();
			return null;
		} finally 
		{
			if (ois != null)
				try
				{
					ois.close();
				} catch (IOException e)
				{ //ok
				}
		}
	}
	
	
	
	public String createResponderKey(X509Certificate issuerCert)
	{
		MessageDigest digest;
		try
		{
			digest = MessageDigest.getInstance("SHA-1");
		} catch (NoSuchAlgorithmException e)
		{
			throw new RuntimeException("JDK problem: SHA-1 hash not supported by any provider!", e);
		}
		PublicKey issuerKey = issuerCert.getPublicKey();
		digest.update(issuerCert.getSubjectX500Principal().getEncoded());
		digest.update(issuerKey.getEncoded());
		return encodeDigest(digest);
	}
	
	private static class ResponderCacheEntry
	{
		private Date maxValidity;
		private IOException error;

		public ResponderCacheEntry(Date maxValidity, IOException error)
		{
			this.maxValidity = maxValidity;
			this.error = error;
		}
	}
}









