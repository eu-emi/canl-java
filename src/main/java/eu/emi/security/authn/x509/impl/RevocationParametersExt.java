/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.impl;

import eu.emi.security.authn.x509.CrlCheckingMode;
import eu.emi.security.authn.x509.OCSPCheckingMode;
import eu.emi.security.authn.x509.OCSPParametes;
import eu.emi.security.authn.x509.RevocationParameters;


/**
 * Manages configuration of revocation settings, used in non-openssl truststores.
 * Currently differs only in case of richer CRL sources settings; OCSP settings are the same as in case
 * of base {@link RevocationParameters}.
 * @author K. Benedyczak
 */
public class RevocationParametersExt extends RevocationParameters implements Cloneable
{
	/**
	 * Constant which can be used to simply turn off any revocation checking.
	 */
	public static final RevocationParametersExt IGNORE = new RevocationParametersExt(
			CrlCheckingMode.IGNORE, new CRLParameters(), new OCSPParametes(OCSPCheckingMode.IGNORE));
	
	protected CRLParameters crlParameters;

	/**
	 * Default constructor, uses default settings of CRLs and OCSP (see 
	 * {@link RevocationParameters#RevocationParameters()} and {@link CRLParameters#CRLParameters()}).
	 */
	public RevocationParametersExt()
	{
		this.crlParameters = new CRLParameters();
	}

	/**
	 * Constructor allowing to set CRL checking mode and all OCSP settings. Default values for overall 
	 * revocation checking are used, see 
	 * {@link RevocationParameters#RevocationParameters(CrlCheckingMode, OCSPParametes)}
	 * @param crlCheckingMode CRL mode
	 * @param crlParameters additional CRL sources and settings
	 * @param ocspParametes OCSP settings
	 */
	public RevocationParametersExt(CrlCheckingMode crlCheckingMode, CRLParameters crlParameters, 
			OCSPParametes ocspParametes)
	{
		super(crlCheckingMode, ocspParametes);
		this.crlParameters = crlParameters;
	}
	
	/**
	 * Full fledged constructor.
	 * @param crlCheckingMode CRL mode
	 * @param crlParameters additional CRL sources and settings
	 * @param ocspParametes OCSP settings
	 * @param useAllEnabled useful only if more then one revocation method is enabled. If this parameter is true
	 * then all enabled revocation sources are tried, even if the first one returns that certificate is valid. 
	 * @param order in what order the configured revocations methods should be tried. 
	 * Significant only if more then one source is enabled.  
	 */
	public RevocationParametersExt(CrlCheckingMode crlCheckingMode, CRLParameters crlParameters, 
			OCSPParametes ocspParametes, boolean useAllEnabled, RevocationCheckingOrder order)
	{
		super(crlCheckingMode, ocspParametes, useAllEnabled, order);
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
			crlParameters.clone(), getOcspParameters(), isUseAllEnabled(), getOrder());
	}
}
