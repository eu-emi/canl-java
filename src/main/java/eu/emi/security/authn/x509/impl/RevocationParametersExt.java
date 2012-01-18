/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.impl;

import eu.emi.security.authn.x509.CrlCheckingMode;
import eu.emi.security.authn.x509.RevocationSettings;


/**
 * Manages configuration of revocation settings, used in non-openssl truststores.
 * Currently only contains CRL sources settings.
 * @author K. Benedyczak
 */
public class RevocationParametersExt extends RevocationSettings implements Cloneable
{
	protected CRLParameters crlParameters;

	/**
	 * Default constructor, uses default settings of CRLs.
	 */
	public RevocationParametersExt()
	{
		this.crlParameters = new CRLParameters();
	}
	
	/**
	 * Constructor.
	 * @param crlParameters CRL parameters to be used
	 */
	public RevocationParametersExt(CrlCheckingMode crlCheckingMode, CRLParameters crlParameters)
	{
		super(crlCheckingMode);
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
	
	public RevocationParametersExt clone()
	{
		return new RevocationParametersExt(getCrlCheckingMode(), 
			crlParameters.clone());
	}
}
