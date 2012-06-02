/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.ocsp;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Hashtable;
import java.util.Map;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.ocsp.OCSPReq;
import org.bouncycastle.ocsp.OCSPResp;
import org.bouncycastle.ocsp.SingleResp;
import org.bouncycastle.util.encoders.Base64;

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
		cache = new Hashtable<String, CacheEntry>(20);
	}
	/**
	 * Returns the checked certificate status.
	 * @param responder mandatory - URL of the responder. HTTP or HTTPs, however in https mode the 
	 * @param toCheckCert mandatory certificate to be checked
	 * @param issuerCert mandatory certificate of the toCheckCert issuer
	 * @param requestor if not null, then it is assumed that request must be signed by the requester.
	 * @param addNonce if true nonce will be added to the request and required in response
	 * @return
	 * @throws OCSPException 
	 */
	public OCSPStatus queryForCertificate(URL responder, X509Certificate toCheckCert,
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
	 * @param requestor if not null, then it is assumed that request must be signed by the requester.
	 * @param addNonce if true nonce will be added to the request and required in response
	 * @param client client to be used for network calls
	 * @return
	 * @throws OCSPException 
	 */
	public OCSPStatus queryForCertificate(URL responder, X509Certificate toCheckCert,
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
			return OCSPStatus.getFromResponse(cachedResp);
		
		OCSPReq request = client.createRequest(toCheckCert, issuerCert, requester, addNonce);
		OCSPResp fullResponse = client.send(responder, request, timeout);
		
		byte[] nonce = OCSPClientImpl.extractNonce(request);
		SingleResp singleResp = client.verifyResponse(fullResponse, toCheckCert, issuerCert, nonce);
		addToCache(key, fullResponse, singleResp);
		return OCSPStatus.getFromResponse(singleResp);
	}
	
	private String createKey(X509Certificate toCheckCert, X509Certificate issuerCert) throws OCSPException
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
		return new String(ascii, ASCII);
	}
	
	private SingleResp getCachedResp(String key, OCSPClientImpl client, X509Certificate toCheckCert, 
			X509Certificate issuerCert) throws IOException, OCSPException
	{
		CacheEntry cachedResp = cache.get(key);
		if (cachedResp == null && diskPath != null)
		{
			File f = new File(diskPath, prefix + key);
			if (f.exists())
			{
				byte[] resp = FileUtils.readFileToByteArray(f);
				OCSPResp fullResp = new OCSPResp(resp);
				SingleResp diskResp = client.verifyResponse(fullResp, toCheckCert, issuerCert, null);
				cachedResp = new CacheEntry(new Date(f.lastModified()), diskResp);
			}
		}
		if (cachedResp == null)
			return null;
		
		Date nextUpdate = cachedResp.response.getNextUpdate();
		Date maxCacheValidity = new Date(cachedResp.date.getTime() + maxTtl);
		if (nextUpdate != null && maxCacheValidity.after(nextUpdate))
			maxCacheValidity = nextUpdate;
		
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
		return cachedResp.response;
	}
	
	private void addToCache(String key, OCSPResp fullResp, SingleResp singleResp) throws IOException
	{
		cache.put(key, new CacheEntry(singleResp));
		if (diskPath != null)
		{
			File f = new File(diskPath, prefix + key);
			if (f.exists())
				f.delete();
			FileUtils.writeByteArrayToFile(f, fullResp.getEncoded());
		}
	}
	
	public void clearMemoryCache()
	{
		cache.clear();
	}
	
	private static class CacheEntry
	{
		private Date date;
		private SingleResp response;
		
		public CacheEntry(SingleResp response)
		{
			this(new Date(), response);
		}

		public CacheEntry(Date date, SingleResp response)
		{
			this.date = date;
			this.response = response;
		}
	}
}









