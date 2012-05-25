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
	
	protected OCSPCheckingMode checkingMode;
	protected OCSPResponder[] localResponders;
	protected int conntectTimeout;
	protected boolean preferLocalResponders;
	protected boolean signRequests;
	protected boolean useNonce;
	
	/**
	 * Default constructor using {@link OCSPCheckingMode#IF_AVAILABLE}.
	 */
	public OCSPParametes()
	{
		this(OCSPCheckingMode.IF_AVAILABLE);
	}

	
	/**
	 * Constructor without any local responders and default settings.
	 * @param checkingMode general checking mode
	 */
	public OCSPParametes(OCSPCheckingMode checkingMode)
	{
		this(checkingMode, new OCSPResponder[0]);
	}

	/**
	 * Uses default settings for timeout ({@link #DEFAULT_TIMEOUT}), prefers local responders,
	 * do not sign requests and do not use nonce. Uses anly a single local responder.
	 * @param checkingMode general checking mode
	 * @param localResponder a single local responder
	 */
	public OCSPParametes(OCSPCheckingMode checkingMode, OCSPResponder localResponder)
	{
		this(checkingMode, new OCSPResponder[] {localResponder});
	}
	
	/**
	 * Uses default settings for timeout ({@link #DEFAULT_TIMEOUT}), prefers local responders,
	 * do not sign requests and do not use nonce. 
	 * @param checkingMode general checking mode
	 * @param localResponders list of local responders (can be empty, but not null)
	 */
	public OCSPParametes(OCSPCheckingMode checkingMode, OCSPResponder[] localResponders)
	{
		this(checkingMode, localResponders, DEFAULT_TIMEOUT, true, false, false);
	}

	/**
	 * Full constructor
	 * @param checkingMode general checking mode
	 * @param localResponders list of local responders (can be empty, but not null)
	 * @param conntectTimeout OCSP responder connection and communication timeout
	 * @param preferLocalResponders whether to prefer locally defined responders over certificate-defined responder
	 * @param signRequests whether to digitally sign requests
	 * @param useNonce whether to use in request and require in response the nonce
	 */
	public OCSPParametes(OCSPCheckingMode checkingMode, OCSPResponder[] localResponders,
			int conntectTimeout, boolean preferLocalResponders, boolean signRequests,
			boolean useNonce)
	{
		this.checkingMode = checkingMode;
		this.localResponders = localResponders;
		this.conntectTimeout = conntectTimeout;
		this.preferLocalResponders = preferLocalResponders;
		this.signRequests = signRequests;
		this.useNonce = useNonce;
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
	 * @return the signRequests
	 */
	public boolean isSignRequests()
	{
		return signRequests;
	}

	/**
	 * @param signRequests the signRequests to set
	 */
	public void setSignRequests(boolean signRequests)
	{
		this.signRequests = signRequests;
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
}
