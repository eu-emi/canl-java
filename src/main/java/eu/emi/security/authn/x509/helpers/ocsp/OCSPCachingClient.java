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
import java.net.URL;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;

import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.util.encoders.Base64;

import eu.emi.security.authn.x509.OCSPParametes;
import eu.emi.security.authn.x509.X509Credential;

/**
 * OCSP client which adds a cache layer on top of {@link OCSPClientImpl}.
 * This class is thread safe.
 * @author K. Benedyczak
 */
public class OCSPCachingClient
{
	private static final Charset ASCII = Charset.forName("US-ASCII");
	private final long maxTtl;
	private final File diskPath;
	private final String prefix;
	private Map<String, CacheEntry> cache;
	
	/**
	 * 
	 * @param maxTtl maximum time after each cached response expires. Negative for no cache at all, 0 for no limit
	 * (i.e. caching time will be only controlled by the OCSP response validity period). In ms.
	 * @param diskPath if not null, cached responses will be stored on disk.
	 * @param prefix used if disk cache is enabled, as a common prefix for all files created in the cache directory. 
	 */
	public OCSPCachingClient(long maxTtl, File diskPath, String prefix)
	{
		this.maxTtl = maxTtl;
		this.diskPath = diskPath;
		this.prefix = (prefix == null) ? "" : prefix;
		cache = Collections.synchronizedMap(new BoundedSizeLruMap());
	}
	/**
	 * Returns the checked certificate status.
	 * @param responder mandatory - URL of the responder. HTTP or HTTPs, however in https mode the 
	 * @param toCheckCert mandatory certificate to be checked
	 * @param issuerCert mandatory certificate of the toCheckCert issuer
	 * @param requester if not null, then it is assumed that request must be signed by the requester.
	 * @param addNonce if true nonce will be added to the request and required in response
	 * @return raw result of the query
	 * @throws OCSPException 
	 */
	public OCSPResult queryForCertificate(URL responder, X509Certificate toCheckCert,
			X509Certificate issuerCert, X509Credential requester, boolean addNonce,
			int timeout) throws IOException, OCSPException
	{
		return queryForCertificate(responder, toCheckCert, issuerCert, requester, addNonce, timeout, 
				new OCSPClientImpl());
	}
	
	/**
	 * Returns the checked certificate status, using a custom client.  
	 * @param responder mandatory - URL of the responder. HTTP or HTTPs, however in https mode the 
	 * @param toCheckCert mandatory certificate to be checked
	 * @param issuerCert mandatory certificate of the toCheckCert issuer
	 * @param requester if not null, then it is assumed that request must be signed by the requester.
	 * @param addNonce if true nonce will be added to the request and required in response
	 * @param client client to be used for network calls
	 * @return raw result of the query
	 * @throws OCSPException 
	 */
	public OCSPResult queryForCertificate(URL responder, X509Certificate toCheckCert,
			X509Certificate issuerCert, X509Credential requester, boolean addNonce,
			int timeout, OCSPClientImpl client) throws IOException, OCSPException
	{
		if (maxTtl < 0)
		{
			return client.queryForCertificate(responder, toCheckCert, issuerCert, 
					requester, addNonce, timeout);
		}
		
		String key = createKey(toCheckCert, issuerCert);
		SingleResp cachedResp = getCachedResp(key, client, toCheckCert, issuerCert);
		if (cachedResp != null)
			return new OCSPResult(cachedResp);
		
		OCSPReq request = client.createRequest(toCheckCert, issuerCert, requester, addNonce);
		OCSPResponseStructure responseWithMeta;
		try
		{
			responseWithMeta = client.send(responder, request, timeout);
		} catch (IOException e)
		{
			addErrorToCache(key, e);
			throw e;
		}
		OCSPResp fullResponse = responseWithMeta.getResponse();
		
		byte[] nonce = OCSPClientImpl.extractNonce(request);
		SingleResp singleResp = client.verifyResponse(fullResponse, toCheckCert, issuerCert, nonce);
		addToCache(key, responseWithMeta, singleResp);
		return new OCSPResult(singleResp);
	}
	
	private String createKey(X509Certificate toCheckCert, X509Certificate issuerCert)
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

		byte[] shortBytes = digest.digest();
		byte[] ascii = Base64.encode(shortBytes);
		String ret = new String(ascii, ASCII);
		return ret.replace('/', '_');
	}
	
	private SingleResp getCachedResp(String key, OCSPClientImpl client, X509Certificate toCheckCert, 
			X509Certificate issuerCert) throws IOException
	{
		CacheEntry cachedResp = cache.get(key);
		if (cachedResp == null && diskPath != null)
		{
			File f = new File(diskPath, prefix + key);
			if (f.exists())
				cachedResp = loadFromDisk(f, client, toCheckCert, issuerCert);
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
			cache.remove(key);
			if (diskPath != null)
			{
				File f = new File(diskPath, prefix + key);
				f.delete();
			}
			return null;
		}
		
		if (cachedResp.error != null)
			throw cachedResp.error;
		
		return cachedResp.response;
	}
	
	private void addToCache(String key, OCSPResponseStructure fullResp, SingleResp singleResp) throws IOException
	{
		if (fullResp.getMaxCache() == null)
			fullResp.setMaxCache(singleResp.getNextUpdate());

		cache.put(key, new CacheEntry(new Date(), fullResp.getMaxCache(), singleResp));
		if (diskPath != null)
		{
			File f = new File(diskPath, prefix + key);
			storeToDisk(f, fullResp);
		}
	}
	
	private void addErrorToCache(String key, IOException error) throws IOException
	{
		long ttl = maxTtl == 0 ? OCSPParametes.DEFAULT_CACHE : maxTtl;
		Date expiry = new Date(System.currentTimeMillis() + ttl);
		cache.put(key, new CacheEntry(new Date(), expiry, error));
	}
	
	
	public void clearMemoryCache()
	{
		cache.clear();
	}
	
	private static class CacheEntry
	{
		private Date cacheDate;
		private Date maxValidity;
		private SingleResp response;
		private IOException error;
		
		private CacheEntry(Date cacheDate, Date maxValidity)
		{
			this.cacheDate = cacheDate;
			this.maxValidity = maxValidity;
		}
		
		public CacheEntry(Date cacheDate, Date maxValidity, SingleResp response)
		{
			this(cacheDate, maxValidity);
			this.response = response;
		}

		public CacheEntry(Date cacheDate, Date maxValidity, IOException e)
		{
			this(cacheDate, maxValidity);
			this.error = e;
		}
	}
	
	private void storeToDisk(File f, OCSPResponseStructure fullResp) throws IOException
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
	
	private CacheEntry loadFromDisk(File f, OCSPClientImpl client, X509Certificate toCheckCert, 
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
			return new CacheEntry(new Date(f.lastModified()), maxCache, diskResp);
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
	
	
	public class BoundedSizeLruMap extends LinkedHashMap<String, CacheEntry>
	{
		private final int MAX = 50;

		public BoundedSizeLruMap()
		{
			super(20, 0.75f, true);
		}

		@Override
		protected boolean removeEldestEntry(Map.Entry<String, CacheEntry> eldest)
		{
			return size() > MAX;
		}
	}
}









