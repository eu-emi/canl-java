/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.ocsp;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.security.cert.X509Certificate;

import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.ocsp.OCSPReq;
import org.bouncycastle.ocsp.OCSPResp;
import org.bouncycastle.ocsp.SingleResp;

import eu.emi.security.authn.x509.X509Credential;

/**
 * OCSP client which adds a cache layer on top of {@link OCSPClientImpl}.
 * There are two caches (all of them are configurable) consulted in the given order:
 * unresponsive responders cache (per responder); OCSP responses cache (per responder and checked certificate tuple).
 * <p>
 * This class is thread safe.
 * @author K. Benedyczak
 */
public class OCSPCachingClient
{
	private final long maxTtl;
	private OCSPRespondersCache respondersCache;
	private OCSPResponsesCache responsesCache;
	
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
		responsesCache = new OCSPResponsesCache(maxTtl, diskPath, prefix);
		respondersCache = new OCSPRespondersCache(maxTtl, diskPath, prefix);
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
		
		String responderKey = respondersCache.createResponderKey(issuerCert);
		respondersCache.checkCachedError(responderKey);
		
		String responseKey = responsesCache.createResponseKey(toCheckCert, issuerCert);		
		SingleResp cachedResp = responsesCache.getCachedResp(responseKey, client, 
				toCheckCert, issuerCert);
		if (cachedResp != null)
			return new OCSPResult(cachedResp);
		
		OCSPReq request = client.createRequest(toCheckCert, issuerCert, requester, addNonce);
		OCSPResponseStructure responseWithMeta;
		try
		{
			responseWithMeta = client.send(responder, request, timeout);
		} catch (IOException e)
		{
			respondersCache.addToCache(responderKey, e);
			throw e;
		}
		OCSPResp fullResponse = responseWithMeta.getResponse();
		
		byte[] nonce = OCSPClientImpl.extractNonce(request);
		SingleResp singleResp = client.verifyResponse(fullResponse, toCheckCert, issuerCert, nonce);
		responsesCache.addToCache(responseKey, responseWithMeta, singleResp);
		return new OCSPResult(singleResp);
	}

	
	public void clearMemoryCache()
	{
		responsesCache.clearMemoryCache();
		respondersCache.clearMemoryCache();
	}
}









