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

import org.bouncycastle.ocsp.OCSPResp;
import org.bouncycastle.ocsp.SingleResp;


/**
 * OCSP responses cache: in memory with disk persistence.
 * 
 * @author K. Benedyczak
 */
public class OCSPResponsesCache extends OCSPCacheBase
{
	private Map<String, ResponseCacheEntry> responsesCache;
	
	/**
	 * 
	 * @param maxTtl maximum time after each cached response expires. Negative for no cache at all, 0 for no limit
	 * (i.e. caching time will be only controlled by the OCSP response validity period). In ms.
	 * @param diskPath if not null, cached responses will be stored on disk.
	 * @param prefix used if disk cache is enabled, as a common prefix for all files created in the cache directory. 
	 */
	public OCSPResponsesCache(long maxTtl, File diskPath, String prefix)
	{
		super(maxTtl, diskPath, prefix);
		responsesCache = Collections.synchronizedMap(new BoundedSizeLruMap<String, ResponseCacheEntry>(100));
	}

	/**
	 * 
	 * @param responseKey
	 * @param client
	 * @param toCheckCert
	 * @param issuerCert
	 * @return The cached response if available, null otherwise.
	 * @throws IOException
	 */
	public SingleResp getCachedResp(String responseKey, OCSPClientImpl client, X509Certificate toCheckCert, 
			X509Certificate issuerCert) throws IOException
	{
		ResponseCacheEntry cachedResp = responsesCache.get(responseKey);
		if (cachedResp == null && diskPath != null)
		{
			File f = new File(diskPath, prefix + responseKey);
			if (f.exists())
				cachedResp = loadResponseFromDisk(f, client, toCheckCert, issuerCert);
		}
		if (cachedResp == null)
			return null;
		
		Date nextUpdate = cachedResp.response != null ? cachedResp.response.getNextUpdate() : null;
		Date maxCacheValidity = new Date(cachedResp.cacheDate.getTime() + maxTtl);
		if (nextUpdate != null && maxCacheValidity.after(nextUpdate))
			maxCacheValidity = nextUpdate;
		if (maxCacheValidity.after(cachedResp.maxValidity))
			maxCacheValidity = cachedResp.maxValidity;
		
		Date now = new Date();
		if (now.after(maxCacheValidity))
		{
			responsesCache.remove(responseKey);
			if (diskPath != null)
			{
				File f = new File(diskPath, prefix + responseKey);
				f.delete();
			}
			return null;
		}
		
		return cachedResp.response;
	}
	
	public String createResponseKey(X509Certificate toCheckCert, X509Certificate issuerCert)
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
		digest.update(toCheckCert.getSerialNumber().toByteArray());

		return encodeDigest(digest);
	}

	public void addToCache(String key, OCSPResponseStructure fullResp, SingleResp singleResp) throws IOException
	{
		if (fullResp.getMaxCache() == null)
			fullResp.setMaxCache(singleResp.getNextUpdate());

		responsesCache.put(key, new ResponseCacheEntry(new Date(), fullResp.getMaxCache(), singleResp));
		if (diskPath != null)
		{
			File f = new File(diskPath, prefix + key);
			storeResponseToDisk(f, fullResp);
		}
	}
	
	public void clearMemoryCache()
	{
		responsesCache.clear();
	}
	
	private void storeResponseToDisk(File f, OCSPResponseStructure fullResp) throws IOException
	{
		if (f.exists())
			f.delete();
		Date maxCache = fullResp.getMaxCache();
		ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(f));
		try
		{
			oos.writeObject(maxCache);
			oos.writeObject(fullResp.getResponse().getEncoded());
		} finally
		{
			oos.close();
		}
	}

	private ResponseCacheEntry loadResponseFromDisk(File f, OCSPClientImpl client, X509Certificate toCheckCert, 
			X509Certificate issuerCert)
	{
		ObjectInputStream ois = null;
		try
		{
			ois = new ObjectInputStream(new FileInputStream(f));
			Date maxCache = (Date)ois.readObject();
			byte[] resp = (byte[]) ois.readObject();
			OCSPResp fullResp = new OCSPResp(resp);
			SingleResp diskResp = client.verifyResponse(fullResp, toCheckCert, issuerCert, null);
			return new ResponseCacheEntry(new Date(f.lastModified()), maxCache, diskResp);
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

	private static class ResponseCacheEntry
	{
		private Date cacheDate;
		private Date maxValidity;
		private SingleResp response;
		
		public ResponseCacheEntry(Date cacheDate, Date maxValidity, SingleResp response)
		{
			this.cacheDate = cacheDate;
			this.maxValidity = maxValidity;
			this.response = response;
		}
	}
}









