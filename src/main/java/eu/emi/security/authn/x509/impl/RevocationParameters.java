/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.impl;


/**
 * Manages configuration of revocation settings, used in non-openssl truststores.
 * Currently only contains CRL settings, but in future versions this class will be
 * extended to also control other revocation technologies like OCSP.
 * @author K. Benedyczak
 */
public class RevocationParameters implements Cloneable
{
	private CRLParameters crlParameters;

	/**
	 * Default constructor, uses default settings of CRLs.
	 */
	public RevocationParameters()
	{
		this.crlParameters = new CRLParameters();
	}
	
	/**
	 * Constructor.
	 * @param crlParameters CRL parameters to be used
	 */
	public RevocationParameters(CRLParameters crlParameters)
	{
		this.crlParameters = crlParameters;
	}

	/**
	 * Returns CRL parameters
	 * @return  CRL parameters
	 */
	public CRLParameters getCrlParameters()
	{
		return crlParameters;
	}

	/**
	 * Sets CRL parameters to be used.
	 * @param crlParameters  CRL parameters to be used
	 */
	public void setCrlParameters(CRLParameters crlParameters)
	{
		this.crlParameters = crlParameters;
	}
	
	public RevocationParameters clone()
	{
		return new RevocationParameters(crlParameters.clone());
	}
}
