/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509;

import eu.emi.security.authn.x509.impl.RevocationParametersExt;


/**
 * Wraps the information required to control how certificates revocation is checked.
 * Currently two mechanisms can be configured (also together): CRL and OCSP.
 * Each of the mechanisms can have its own options. In case of CRLs this configuration can be even 
 * different depending on validator being used.
 * <p>
 * This class controls also the overall revocation checking process, if more then one revocation 
 * source is enabled. It is possible to choose which is tried first and whether all enabled sources must be used
 * always (useAllEnabled). For instance, let's assume the default revocation checking order (OCSP, CRL) and that both
 * sources are enabled. Then if OCSP returns that certificate is valid and useAllEnabled is true, also the CRL 
 * will be checked. If useAllEnabled is false, then OCSP answer will be sufficient.
 * <p>
 * Note that regardless of the useAllEnabled setting, if the first source returns that the certificate is revoked,
 * the next one will not be used.
 * <p>
 * Finally note that the individual revocation sources settings are the most important anyway. For instance 
 * if both sources are enabled, but in non-requisite modes, then the whole revocation checking can finish in 
 * undetermined state which will be perfectly fine.   
 * 
 * @see RevocationParametersExt
 * @author K. Benedyczak
 */
public class RevocationParameters implements Cloneable
{
	public enum RevocationCheckingOrder {CRL_OCSP, OCSP_CRL};
	
	/**
	 * Constant which can be used to simply turn off any revocation checking.
	 */
	public static final RevocationParameters IGNORE = 
			new RevocationParameters(CrlCheckingMode.IGNORE, new OCSPParametes(OCSPCheckingMode.IGNORE));
	protected CrlCheckingMode crlCheckingMode;
	protected OCSPParametes ocspParameters;
	protected boolean useAllEnabled;
	protected RevocationCheckingOrder order; 
	
	
	/**
	 * Default constructor, using the default {@link CrlCheckingMode#IF_VALID} and default {@link OCSPParametes}.
	 * One positive revocation source is enough to finish validation, order is set to OCSP first, then CRL.
	 */
	public RevocationParameters()
	{
		this(CrlCheckingMode.IF_VALID, new OCSPParametes());
	}
	
	/**
	 * Constructor using default {@link OCSPParametes}
	 * One positive revocation source is enough to finish validation, order is set to OCSP first, then CRL.
	 * @param crlCheckingMode what CRL settings shall be used
	 * @deprecated
	 */
	public RevocationParameters(CrlCheckingMode crlCheckingMode)
	{
		this(crlCheckingMode, new OCSPParametes(), false, RevocationCheckingOrder.OCSP_CRL);
	}

	/**
	 * One positive revocation source is enough to finish validation, order is set to OCSP first, then CRL.
	 * @param crlCheckingMode what CRL settings shall be used
	 * @param ocspCheckingMode what OCSP settings shall be used
	 */
	public RevocationParameters(CrlCheckingMode crlCheckingMode, OCSPParametes ocspParameters)
	{
		this(crlCheckingMode, ocspParameters, false, RevocationCheckingOrder.OCSP_CRL);
	}

	/**
	 * Constructor allowing to control all settings.
	 * @param crlCheckingMode what CRL settings shall be used
	 * @param ocspParametes what OCSP settings shall be used
	 * @param useAllEnabled useful only if more then one revocation method is enabled. If this parameter is true
	 * then all enabled revocation sources are tried, even if the first one returns that certificate is valid. 
	 * @param order in what order the configured revocations methods should be tried. 
	 * Significant only if more then one source is enabled.  
	 */
	public RevocationParameters(CrlCheckingMode crlCheckingMode, OCSPParametes ocspParametes, 
			boolean useAllEnabled, RevocationCheckingOrder order)
	{
		this.crlCheckingMode = crlCheckingMode;
		this.ocspParameters = ocspParametes;
		this.useAllEnabled = useAllEnabled;
		this.order = order;
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
	 * Returns the current OCSP settings.
	 * @return the current OCSP settings
	 */
	public OCSPParametes getOcspParameters()
	{
		return ocspParameters;
	}

	/**
	 * Changes OCSP settings that shall be used.
	 * @param ocspParametes what OCSP settings shall be used
	 */
	public void setOcspParameters(OCSPParametes ocspParametes)
	{
		this.ocspParameters = ocspParametes;
	}

	/**
	 * @return the useAllEnabled
	 */
	public boolean isUseAllEnabled()
	{
		return useAllEnabled;
	}

	/**
	 * @param useAllEnabled the useAllEnabled to set
	 */
	public void setUseAllEnabled(boolean useAllEnabled)
	{
		this.useAllEnabled = useAllEnabled;
	}

	/**
	 * @return the order
	 */
	public RevocationCheckingOrder getOrder()
	{
		return order;
	}

	/**
	 * @param order the order to set
	 */
	public void setOrder(RevocationCheckingOrder order)
	{
		this.order = order;
	}

	/**
	 * Clone the instance
	 */
	public RevocationParameters clone()
	{
		return new RevocationParameters(crlCheckingMode, ocspParameters);
	}
}
