/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509;


/**
 * Wraps the information required to control how certificates revocation is checked.
 * Currently two mechanisms can be configured (also together): CRL and OCSP.
 * 
 *    
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
	protected int sufficient;
	protected RevocationCheckingOrder order; 
	
	
	/**
	 * Default constructor, using the default {@link CrlCheckingMode#IF_VALID} and default {@link OCSPParametes}.
	 * Sufficient is set to 0, order to OCSP_CRL
	 */
	public RevocationParameters()
	{
		this(CrlCheckingMode.IF_VALID, new OCSPParametes());
	}
	
	/**
	 * Constructor using default {@link OCSPParametes}
	 * Sufficient is set to 0, order to OCSP_CRL
	 * @param crlCheckingMode what CRL settings shall be used
	 * @deprecated
	 */
	public RevocationParameters(CrlCheckingMode crlCheckingMode)
	{
		this(crlCheckingMode, new OCSPParametes(), 0, RevocationCheckingOrder.OCSP_CRL);
	}

	/**
	 * Sufficient is set to 0, order to OCSP_CRL
	 * @param crlCheckingMode what CRL settings shall be used
	 * @param ocspCheckingMode what OCSP settings shall be used
	 */
	public RevocationParameters(CrlCheckingMode crlCheckingMode, OCSPParametes ocspParameters)
	{
		this(crlCheckingMode, ocspParameters, 0, RevocationCheckingOrder.OCSP_CRL);
	}

	/**
	 * Constructor.
	 * @param crlCheckingMode what CRL settings shall be used
	 * @param ocspCheckingMode what OCSP settings shall be used
	 * @param sufficient useful only if more then one revocation method is enabled, and at least the first 
	 * enabled method is not in the hard fail mode (i.e. can finish with unknown state). If this parameter is true
	 * then the overall revocation checking status is all assumed to be passed only if that many methods positively
	 * verify the certificate. E.g. 1 means that it is enough that one method verifies the certificate 
	 * (no matter which).
	 * @param order in what order the configured revocations methods should be tried.  
	 */
	public RevocationParameters(CrlCheckingMode crlCheckingMode, OCSPParametes ocspParametes, 
			int sufficient, RevocationCheckingOrder order)
	{
		this.crlCheckingMode = crlCheckingMode;
		this.ocspParameters = ocspParametes;
		this.sufficient = sufficient;
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
	 * @return the sufficient
	 */
	public int getSufficient()
	{
		return sufficient;
	}

	/**
	 * @param sufficient the sufficient to set
	 */
	public void setSufficient(int sufficient)
	{
		this.sufficient = sufficient;
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
