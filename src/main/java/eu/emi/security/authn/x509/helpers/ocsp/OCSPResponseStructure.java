/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.ocsp;

import java.util.Date;

import org.bouncycastle.cert.ocsp.OCSPResp;


/**
 * Holds OCSP response (parsed) and some additional metadata, e.g. extracted from HTTP headers.
 * @author K. Benedyczak
 */
public class OCSPResponseStructure
{
	private OCSPResp response;
	private Date maxCache;

	/**
	 * @param response OSCP response
	 * @param maxCache max cache date
	 */
	public OCSPResponseStructure(OCSPResp response, Date maxCache)
	{
		super();
		this.response = response;
		this.maxCache = maxCache;
	}
	/**
	 * @return the response
	 */
	public OCSPResp getResponse()
	{
		return response;
	}
	/**
	 * @param response the response to set
	 */
	public void setResponse(OCSPResp response)
	{
		this.response = response;
	}
	/**
	 * @return the maxCache
	 */
	public Date getMaxCache()
	{
		return maxCache;
	}
	/**
	 * @param maxCache the maxCache to set
	 */
	public void setMaxCache(Date maxCache)
	{
		this.maxCache = maxCache;
	}
}
