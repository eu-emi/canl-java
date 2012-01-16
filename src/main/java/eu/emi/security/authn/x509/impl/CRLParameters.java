/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.impl;

import java.io.Serializable;
import java.security.cert.CertStoreParameters;
import java.util.ArrayList;
import java.util.List;

/**
 * Manages configuration of CRL sources, used in non-openssl truststores.
 * @author K. Benedyczak
 */
public class CRLParameters implements CertStoreParameters, Serializable
{
	private static final long serialVersionUID = 1L;
	private List<String> crls;
	private long crlUpdateInterval;
	private int remoteConnectionTimeout;
	private String diskCachePath;
	

	/**
	 * 
	 * @param crls the mandatory list of CRLs. May be empty.
	 * @param crlUpdateInterval if <=0 value is passed then CRLs are loaded only once. 
	 * Otherwise it is a time expressed in milliseconds between subsequent CRL updates, as
	 * measured between the end of the last update and the start of the next.
	 * @param remoteConnectionTimeout timeout in milliseconds of the connection and 
	 * reading of the remote CRLs. 0 is treated as infinitive number.
	 */
	public CRLParameters(List<String> crls, long crlUpdateInterval,
			int remoteConnectionTimeout,
			String diskCachePath)
	{
		if (crls == null)
			throw new IllegalArgumentException("CRLs list may not be null");
		if (remoteConnectionTimeout < 0)
			throw new IllegalArgumentException("Remote connection timeout must be a non negative number");
		this.crls = crls;
		this.crlUpdateInterval = crlUpdateInterval;
		this.remoteConnectionTimeout = remoteConnectionTimeout;
		this.diskCachePath = diskCachePath;
	}

	/**
	 * Default constructor uses standard CRL parameters: no CRLs are defined, 
	 * no disk cache, no CRLs updates.
	 */
	public CRLParameters()
	{
		this(new ArrayList<String>(0), -1L, 5000, null);
	}

	public CRLParameters clone()
	{
		List<String> copy = new ArrayList<String>();
		copy.addAll(crls);
		return new CRLParameters(copy, crlUpdateInterval,  
				remoteConnectionTimeout, diskCachePath);
	}
	
	public String getDiskCachePath()
	{
		return diskCachePath;
	}

	public void setDiskCachePath(String diskCachePath)
	{
		this.diskCachePath = diskCachePath;
	}

	public int getRemoteConnectionTimeout()
	{
		return remoteConnectionTimeout;
	}

	public void setRemoteConnectionTimeout(int remoteConnectionTimeout)
	{
		this.remoteConnectionTimeout = remoteConnectionTimeout;
	}

	public List<String> getCrls()
	{
		return crls;
	}

	public void setCrls(List<String> crls)
	{
		this.crls = crls;
	}

	public long getCrlUpdateInterval()
	{
		return crlUpdateInterval;
	}

	public void setCrlUpdateInterval(long crlUpdateInterval)
	{
		this.crlUpdateInterval = crlUpdateInterval;
	}
}
