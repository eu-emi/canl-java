/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509;


/**
 * Wraps the information required to control how certificates revocation is checked.
 * Currently only contains CRL settings, but in future versions this class will be
 * extended to also control other revocation technologies like OCSP.
 *    
 * @author K. Benedyczak
 */
public class RevocationSettings implements Cloneable
{
	protected CrlCheckingMode crlCheckingMode;

	/**
	 * Default constructor, using the default {@link CrlCheckingMode}.REQUIRE
	 */
	public RevocationSettings()
	{
		this.crlCheckingMode = CrlCheckingMode.REQUIRE;
	}
	
	/**
	 * Constructor.
	 * @param crlCheckingMode what CRL settings shall be used
	 */
	public RevocationSettings(CrlCheckingMode crlCheckingMode)
	{
		this.crlCheckingMode = crlCheckingMode;
	}

	/**
	 * Returns the current CRL settings.
	 * @return the current CRL settings
	 */
	public CrlCheckingMode getCrlCheckingMode()
	{
		return crlCheckingMode;
	}

	/**
	 * Changes CRL settings that shall be used.
	 * @param crlCheckingMode what CRL settings shall be used
	 */
	public void setCrlCheckingMode(CrlCheckingMode crlCheckingMode)
	{
		this.crlCheckingMode = crlCheckingMode;
	}
	
	/**
	 * Clone the instance
	 */
	public RevocationSettings clone()
	{
		return new RevocationSettings(crlCheckingMode);
	}
}
