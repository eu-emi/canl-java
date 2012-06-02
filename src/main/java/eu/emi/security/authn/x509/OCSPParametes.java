/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509;


/**
 * Manages configuration of OCSP support for all truststores.
 * @author K. Benedyczak
 */
public class OCSPParametes
{
	public static final int DEFAULT_TIMEOUT = 10000;
	public static final int DEFAULT_CACHE = 3600;
	
	protected OCSPCheckingMode checkingMode;
	protected OCSPResponder[] localResponders;
	protected int conntectTimeout;
	protected boolean preferLocalResponders;
	protected boolean useNonce;
	protected int cacheTtl;
	protected String diskCachePath;
	
	
	/**
	 * Default constructor using {@link OCSPCheckingMode#IF_AVAILABLE}.
	 * @see #OCSPParametes(OCSPCheckingMode) 
	 */
	public OCSPParametes()
	{
		this(OCSPCheckingMode.IF_AVAILABLE);
	}

	
	/**
	 * Constructor without any local responders and default settings.
	 * @param checkingMode general checking mode
	 * @see #OCSPParametes(OCSPCheckingMode, OCSPResponder)
	 */
	public OCSPParametes(OCSPCheckingMode checkingMode)
	{
		this(checkingMode, new OCSPResponder[0], DEFAULT_CACHE, null);
	}

	/**
	 * Uses default settings for timeout ({@link #DEFAULT_TIMEOUT}), and cache ({@link #DEFAULT_CACHE} and
	 * no disk persistence of cached responses), prefers local responders,
	 * do not sign requests and do not use nonce. Uses only a single local responder.
	 * @param checkingMode general checking mode
	 * @param localResponder a single local responder
	 */
	public OCSPParametes(OCSPCheckingMode checkingMode, OCSPResponder localResponder)
	{
		this(checkingMode, new OCSPResponder[] {localResponder}, DEFAULT_CACHE, null);
	}
	
	/**
	 * Uses default settings for timeout ({@link #DEFAULT_TIMEOUT}), prefers local responders,
	 * do not sign requests and do not use nonce. 
	 * @param checkingMode general checking mode
	 * @param localResponders list of local responders (can be empty, but not null)
	 * @param cacheTtl maximum time after each cached response expires. Negative for no cache at all, 0 for no limit
	 * (i.e. caching time will be only controlled by the OCSP response validity period). In s.
	 * @param diskCachePath if not null, cached responses will be stored on disk.
	 */
	public OCSPParametes(OCSPCheckingMode checkingMode, OCSPResponder[] localResponders, int cacheTtl, 
			String diskCachePath)
	{
		this(checkingMode, localResponders, DEFAULT_TIMEOUT, true, false, cacheTtl, diskCachePath);
	}

	/**
	 * Full constructor
	 * @param checkingMode general checking mode
	 * @param localResponders list of local responders (can be empty, but not null)
	 * @param conntectTimeout OCSP responder connection and communication timeout
	 * @param preferLocalResponders whether to prefer locally defined responders over certificate-defined responder
	 * @param useNonce whether to use in request and require in response the nonce
	 * @param cacheTtl maximum time after each cached response expires. Negative for no cache at all, 0 for no limit
	 * (i.e. caching time will be only controlled by the OCSP response validity period). In s.
	 * @param diskCachePath if not null, cached responses will be stored on disk.
	 */
	public OCSPParametes(OCSPCheckingMode checkingMode, OCSPResponder[] localResponders,
			int conntectTimeout, boolean preferLocalResponders, 
			boolean useNonce, int cacheTtl, String diskCachePath)
	{
		this.checkingMode = checkingMode;
		this.localResponders = localResponders;
		this.conntectTimeout = conntectTimeout;
		this.preferLocalResponders = preferLocalResponders;
		this.useNonce = useNonce;
		this.cacheTtl = cacheTtl;
		this.diskCachePath = diskCachePath;
	}

	/**
	 * @return the checkingMode
	 */
	public OCSPCheckingMode getCheckingMode()
	{
		return checkingMode;
	}

	/**
	 * @param checkingMode the checkingMode to set
	 */
	public void setCheckingMode(OCSPCheckingMode checkingMode)
	{
		this.checkingMode = checkingMode;
	}

	/**
	 * @return the localResponders
	 */
	public OCSPResponder[] getLocalResponders()
	{
		return localResponders;
	}

	/**
	 * @param localResponders the localResponders to set
	 */
	public void setLocalResponders(OCSPResponder[] localResponders)
	{
		this.localResponders = localResponders;
	}

	/**
	 * @return the conntectTimeout
	 */
	public int getConntectTimeout()
	{
		return conntectTimeout;
	}

	/**
	 * @param conntectTimeout the conntectTimeout to set
	 */
	public void setConntectTimeout(int conntectTimeout)
	{
		this.conntectTimeout = conntectTimeout;
	}

	/**
	 * @return the preferLocalResponders
	 */
	public boolean isPreferLocalResponders()
	{
		return preferLocalResponders;
	}

	/**
	 * @param preferLocalResponders the preferLocalResponders to set
	 */
	public void setPreferLocalResponders(boolean preferLocalResponders)
	{
		this.preferLocalResponders = preferLocalResponders;
	}

	/**
	 * @return the useNonce
	 */
	public boolean isUseNonce()
	{
		return useNonce;
	}

	/**
	 * @param useNonce the useNonce to set
	 */
	public void setUseNonce(boolean useNonce)
	{
		this.useNonce = useNonce;
	}


	/**
	 * @return the cacheTtl
	 */
	public int getCacheTtl()
	{
		return cacheTtl;
	}


	/**
	 * @param cacheTtl the cacheTtl to set
	 */
	public void setCacheTtl(int cacheTtl)
	{
		this.cacheTtl = cacheTtl;
	}


	/**
	 * @return the diskCachePath
	 */
	public String getDiskCachePath()
	{
		return diskCachePath;
	}


	/**
	 * @param diskCachePath the diskCachePath to set
	 */
	public void setDiskCachePath(String diskCachePath)
	{
		this.diskCachePath = diskCachePath;
	}
}
