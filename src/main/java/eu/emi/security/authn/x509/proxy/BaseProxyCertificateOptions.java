/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 * 
 * Parts of this class are derived from the glite.security.util-java module, 
 * copyrighted as follows:
 *
 * Copyright (c) Members of the EGEE Collaboration. 2004. See
 * http://www.eu-egee.org/partners/ for details on the copyright holders.
 */
package eu.emi.security.authn.x509.proxy;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.x509.AttributeCertificate;
import org.bouncycastle.asn1.x509.KeyUsage;

import eu.emi.security.authn.x509.helpers.proxy.ProxyAddressRestrictionData;
import eu.emi.security.authn.x509.impl.CertificateUtils;


/**
 * Generic proxy creation parameters useful for all scenarios.
 * All objects passed to this class are copied. All objects returned by methods of this class are also
 * copies of the object state. Therefore it is only possible to modify state of this class using its methods.
 * This class is not thread safe.
 * 
 * @author J. Hahkala
 * @author K. Benedyczak
 */
public abstract class BaseProxyCertificateOptions
{
	static 
	{
		CertificateUtils.configureSecProvider();
	}

	/**
	 * Key usage value which is used when 
	 */
	public static final int DEFAULT_KEY_USAGE = KeyUsage.dataEncipherment
			| KeyUsage.digitalSignature | KeyUsage.keyEncipherment;
	
	public static final int DEFAULT_LIFETIME = 12*3600;
	private final X509Certificate[] parentChain;
	
	private int lifetime = DEFAULT_LIFETIME;
	private Date notBefore;
	private ProxyType type;
	private boolean limited = false;
	private BigInteger serialNumber = null;
	private int proxyPathLimit = -1;
	private int proxyKeyUsageMask = -1;

	private List<CertificateExtension> extensions;
	private ProxyPolicy policy = null;
	private String[] targetRestrictionPermitted;
	private String[] targetRestrictionExcluded;
	private String[] sourceRestrictionPermitted;
	private String[] sourceRestrictionExcluded;
	private String proxyTracingSubject;
	private String proxyTracingIssuer;
	private String samlAssertion;
	private AttributeCertificate[] attributeCertificates;
	
	/**
	 * Create a new proxy cert based on the parent cert chain.
	 * The default type of the proy generation params will be set to the type of the
	 * parent chain if it is an consistent proxy chain. If it is mixed proxy chain, 
	 * or EEC certificate chain then by default RFC proxy type is set.
	 * @param parentCertChain chain of the issuer
	 */
	protected BaseProxyCertificateOptions(X509Certificate[] parentCertChain)
	{
		if (parentCertChain == null || parentCertChain.length == 0)
			throw new IllegalArgumentException("parent certificate chain must be set");
		this.parentChain = Arrays.copyOf(parentCertChain, parentCertChain.length);
		extensions = new ArrayList<CertificateExtension>();
		notBefore = new Date();
		
		if (ProxyUtils.isProxy(parentCertChain))
		{
			ProxyChainType pct;
			try
			{
				pct = new ProxyChainInfo(parentCertChain).getProxyType();
			} catch (CertificateException e)
			{
				throw new IllegalArgumentException("Can not parse the parentCertChain argument", e);
			}
			if (pct == ProxyChainType.RFC3820)
				type = ProxyType.RFC3820;
			else if (pct == ProxyChainType.DRAFT_RFC)
				type = ProxyType.DRAFT_RFC;
			else if (pct == ProxyChainType.LEGACY)
				type = ProxyType.LEGACY;
			else
				type = ProxyType.RFC3820;
		} else
			type = ProxyType.RFC3820;

// Removed see issue #64. When creating legacy proxies the requirement to have digSig KU is not formally 
// enforced (err there is no formal definition) so we can't perform a sanity check here.
		
//		Integer parentKU = ProxyGeneratorHelper.getChainKeyUsage(parentCertChain);
//		if (parentKU != null && ((parentKU & KeyUsage.digitalSignature) == 0))
//			throw new IllegalArgumentException("The parent certificate chain has no digital signature" +
//					" bit set in its Key Usage. This chain can not be used to create proxies.");
	}

	/**
	 * Returns the certificate parent chain of the proxy. If only user certificate
	 * was provided then it is returned in a one element array.
	 * @return the parent certificate chain
	 */
	public X509Certificate[] getParentCertChain()
	{
		return parentChain;
	}

	/**
	 * Sets the desired time bounds for the proxy. Note that both arguments are cut to the 
	 * seconds precision (this is what goes into certificate).
	 * @param notBefore proxy won't be valid before this date
	 * @param notAfter proxy won't be valid after this date 
	 * @since 1.1.0
	 */
	public void setValidityBounds(Date notBefore, Date notAfter)
	{
		
		this.notBefore = new Date();
		this.notBefore.setTime((notBefore.getTime()/1000L)*1000);
		if (notAfter.before(notBefore))
			throw new IllegalArgumentException("notBefore argument value must be earlier than notAfter");
		this.lifetime =  (int)(notAfter.getTime()/1000L - notBefore.getTime()/1000L);
	}
	
	/**
	 * Set the proxy lifetime in seconds. The start of proxy validity is set to the current time. 
	 * If not set, the default lifetime is 12h. 
	 *  
	 * @param lifetime in seconds
	 * @see #setValidityBounds(Date, Date)
	 */
	public void setLifetime(int lifetime)
	{
		this.notBefore = new Date();
		this.lifetime = lifetime;
	}

	/**
	 * Set the proxy lifetime using desired unit.  The start of proxy validity is set to the current time. 
	 * If not set, the default lifetime is 12h. 
	 * @param lifetime in unit specified by the 2nd parameter
	 * @param unit the unit of the timeout specified by the first value
	 * @throws IllegalArgumentException if the requested lifetime is larger then 
	 * {@link Integer#MAX_VALUE} seconds. 
	 * @see #setValidityBounds(Date, Date)
	 * @since 1.1.0
	 */
	public void setLifetime(long lifetime, TimeUnit unit)
	{
		long secLifetime = unit.toSeconds(lifetime);
		if (secLifetime > (long)Integer.MAX_VALUE)
			throw new IllegalArgumentException("This implementation allows for proxy lifetimes up to " +
					Integer.MAX_VALUE + " seconds");
		setLifetime((int)secLifetime);
	}

	/**
	 * 
	 * @return proxy lifetime in seconds
	 */
	public int getLifetime()
	{
		return lifetime;
	}

	/**
	 * 
	 * @return start of proxy validity
	 */
	public Date getNotBefore()
	{
		return notBefore;
	}

	/**
	 * @return bit mask of KeyUsage flags which was set for the options object or -1 if nothing was set.
	 */
	public int getProxyKeyUsageMask()
	{
		return proxyKeyUsageMask;
	}

	/**
	 * Sets the mask of the KeyUsage for the resulting proxy certificate. Note that the this is a mask,
	 * i.e. the flags from this mask are ANDed with the effective KeyUsage of the parent chain.
	 * <p>
	 * If this method is not called at all (or called with a negative argument), then the default behavior
	 * is applied, and the proxy gets a copy of the effective KeyUsage of the parent chain. If no certificate
	 * in the parent chain has KeyUsage set, then the {@link #DEFAULT_KEY_USAGE} is applied.     
	 * @param proxyKeyUsageMask The mask to set. Use constants from the {@link KeyUsage} class. The mask must always
	 * have the {@link KeyUsage#digitalSignature} bit set.
	 * @throws IllegalArgumentException if the argument has no {@link KeyUsage#digitalSignature} bit set
	 */
	public void setProxyKeyUsageMask(int proxyKeyUsageMask) throws IllegalArgumentException
	{
		if ((proxyKeyUsageMask & KeyUsage.digitalSignature) == 0)
			throw new IllegalArgumentException("The digital signature bit must be always set for the proxy");
		this.proxyKeyUsageMask = proxyKeyUsageMask;
	}

	/**
	 * Used to set the type of the proxy. Useful only in case the parent
	 * certificate is user certificate, otherwise the generator will
	 * generate same type of proxy as the parent is. And trying to set
	 * different type here than in the parent will result in
	 * IllegalArgumentException. If the parent certificate is user
	 * certificate and this method is not used,
	 * RFC3820 type will be assumed.
	 * @param type to be set
	 */
	public void setType(ProxyType type) throws IllegalArgumentException
	{
		this.type = type;
	}

	/**
	 * @return the current proxy type
	 */
	public ProxyType getType()
	{
		return type;
	}

	/**
	 * Defines whether the resulting proxy will be a limited proxy. Job
	 * submission with a limited proxy is not possible.
	 * <p>
	 * For legacy proxy this is the only way to control the proxy's application area.
	 * RFC and draft proxies allows for a more rich and extensible semantics using 
	 * {@link #setPolicy(ProxyPolicy)}. 
	 * <p>
	 * Since version 1.2.0, in case of RFC proxies, usage of this method with argument 'true' is
	 * equivalent to calling <code>setPolicy(new ProxyPolicy(ProxyPolicy.LIMITED_PROXY_OID))</code>
	 * and with argument false to <code>setPolicy(new ProxyPolicy(ProxyPolicy.INHERITALL_POLICY_OID))</code>.
	 * Note that subsequent calls to setPolicy will overwrite the setLimited setting. Therefore the following 
	 * code:
	 * <pre>
	 * param.setLimited(true);
	 * param.setPolicy(new ProxyPolicy(ProxyPolicy.INHERITALL_POLICY_OID));
	 * </pre>
	 * configures the engine to create limited legacy proxies or unlimited rfc proxies. 
	 * As this behavior is rather not intended it is strongly advised NOT to mix 
	 * setLimited and setPolicy calls in any case.
	 * 
	 * @param limited true if proxy shall be limited
	 */
	public void setLimited(boolean limited)
	{
		this.limited = limited;
		if (limited)
			setPolicy(new ProxyPolicy(ProxyPolicy.LIMITED_PROXY_OID));
		else
			setPolicy(new ProxyPolicy(ProxyPolicy.INHERITALL_POLICY_OID));
	}

	/**
	 * Checks if the proxy shall be limited.
	 * @return true if limited proxy shall be created
	 */
	public boolean isLimited()
	{
		return limited;
	}

	/**
	 * Sets the proxy serial number. Only applicable for rfc proxies.
	 * @param sn serial number to be set
	 */
	public void setSerialNumber(BigInteger sn)
	{
		this.serialNumber = sn;
	}

	/**
	 * Gets the proxy serial number.
	 * @return the serial number previously set
	 */
	public BigInteger getSerialNumber()
	{
		return serialNumber;
	}

	/**
	 * Sets the proxy path length limit of this certificate. Only works on
	 * rfc3820 and RFC draft proxies.
	 * @param pathLen path limit, use negative value if proxy shall be unlimited
	 */
	public void setProxyPathLimit(int pathLen)
	{
		this.proxyPathLimit = pathLen;
	}
	
	/**
	 * Gets the proxy path length limit of this certificate.
	 * @return limit or -1 if proxy shall be unlimited
	 */
	public int getProxyPathLimit()
	{
		return proxyPathLimit;
	}

	
	
	///////////////////////////////////////////////////////////////////////
	//////////// DIRECT EXTENSIONS HANDLING ///////////////////////////////
	///////////////////////////////////////////////////////////////////////
	
	
	
	
	
	/**
	 * Add an extension to the proxy certificate to be generated.
	 * @param extension the extension to be set
	 */
	public void addExtension(CertificateExtension extension)
	{
		extensions.add(extension);
	}

	/**
	 * @return Returns a list of extensions including only those which were set via 
	 * {@link #addExtension(CertificateExtension)}
	 */
	public List<CertificateExtension> getExtensions()
	{
		List<CertificateExtension> ret = new ArrayList<CertificateExtension>(extensions.size());
		ret.addAll(extensions);
		return ret;
	}
	

	/**
	 * Set the RFC proxy extension policy OID and octets of the
	 * policy. See RFC3820. Policy can be null in case the OID in it self
	 * defines the behavior, like with "inherit all" policy or
	 * "independent" policy.
	 * <p>
	 * Note: this setting is ignored for legacy proxies.
	 * @param policy to be set
	 */
	public void setPolicy(ProxyPolicy policy)
	{
		this.policy = policy.clone();
	}

	/**
	 * @return Get the RFC proxy extension policy OID and octets of the
	 * policy. See RFC3820. Policy can be null in case the OID in it self
	 * defines the behavior, like with "inherit all" policy or
	 * "independent" policy.
	 */
	public ProxyPolicy getPolicy()
	{
		return policy == null ? null : policy.clone();
	}
	
	/**
	 * Sets a new permitted target IP addressSpace to the Proxy.
	 *
	 * @param addresses The address space to add to the allowed ip address space. 
	 * Example of the format: 192.168.0.0/16.
	 * It equals to a network 192.168.0.0 with a net mask 255.255.0.0. 
	 * A single IP address can be defined as xxx.xxx.xxx.xxx/32. <br>
	 * See <a href="http://www.ietf.org/rfc/rfc4632.txt"> RFC 4632.</a> 
	 * The restriction is of the format used for NameConstraints, 
	 * meaning GeneralName with 8 octets for ipv4 and 32 octets for ipv6 addresses.
	 * @throws IllegalArgumentException if the argument does not contain addresses in
	 * the specified format 
	 */
	public void setTargetRestrictionPermittedAddresses(String[] addresses)
		throws IllegalArgumentException
	{
		targetRestrictionPermitted = addresses.clone();
	}
	
	/**
	 * Sets a permitted target IP address space to the Proxy.
	 * 
	 * @param addresses The array of 8 element arrays of bytes 
	 * representation of address spaces defined in this structure. 
	 * Each inner 8-elements array must contains IP address and netmask bytes,  
	 * e.g. {137,138,0,0,255,255,0,0}.
	 * @throws IllegalArgumentException when inner arrays are not of length 8
	 * or if does not represent a valid address and netmask combination.
	 */
	public void setTargetRestrictionPermittedAddresses(byte[][] addresses) 
		throws IllegalArgumentException
	{
		targetRestrictionPermitted = ProxyAddressRestrictionData.convert2strings(addresses);
	}
	
	/**
	 * Returns a permitted target IP address space of the Proxy.
	 * 
	 * @return The array of addresses in the CIDR format (address/netmaskBits)
	 * or null if not set
	 */
	public String[] getTargetRestrictionPermittedAddresses()
	{
		return targetRestrictionPermitted == null ? null :
				targetRestrictionPermitted.clone();
	}

	/**
	 * Sets a new permitted source IP addressSpace to the Proxy
	 *
	 * @param addresses The address space to add to the allowed ip address space. 
	 * Example of the format: 192.168.0.0/16.
	 * It equals a 192.168.0.0 with a net mask 255.255.0.0. 
	 * A single IP address can be defined as xxx.xxx.xxx.xxx/32. <br>
	 * See <a href="http://www.ietf.org/rfc/rfc4632.txt"> RFC 4632.</a> 
	 * The restriction is of the format used for NameConstraints, 
	 * meaning GeneralName with 8 octets for ipv4 and 32 octets for ipv6 addresses.
	 * @throws IllegalArgumentException if the argument does not contain addresses in
	 * the specified format 
	 */
	public void setSourceRestrictionPermittedAddresses(String[] addresses)
		throws IllegalArgumentException
	{
		sourceRestrictionPermitted = addresses.clone();
	}
	
	/**
	 * Sets a permitted source IP addressSpace to the Proxy.
	 * 
	 * @param addresses The array of 8 element arrays of bytes 
	 * representation of address spaces defined in this structure. 
	 * Each inner 8-elements array must contains IP address and netmask bytes,  
	 * e.g. {137,138,0,0,255,255,0,0}.
	 * @throws IllegalArgumentException when inner arrays are not of length 8
	 * or if does not represent a valid address and netmask combination.
	 */
	public void setSourceRestrictionPermittedAddresses(byte[][] addresses)
		throws IllegalArgumentException
	{
		sourceRestrictionPermitted = ProxyAddressRestrictionData.convert2strings(addresses);
	}
	
	/**
	 * Gets the permitted source IP addressSpace of the Proxy.
	 * 
	 * @return The array of addresses in the CIDR format (address/netmaskBits)
	 * or null if not set
	 */
	public String[] getSourceRestrictionPermittedAddresses()
	{
		return sourceRestrictionPermitted == null ? null :
				sourceRestrictionPermitted.clone();
	}

	/**
	 * Sets an excluded target IP addressSpace to the data structure.
	 * 
	 * @param addresses The address space to add to the allowed ip address space. 
	 * Example of the format: 192.168.0.0/16.
	 * It equals a 192.168.0.0 with a net mask 255.255.0.0. 
	 * A single IP address can be defined as xxx.xxx.xxx.xxx/32. <br>
	 * See <a href="http://www.ietf.org/rfc/rfc4632.txt"> RFC 4632.</a> 
	 * The restriction is of the format used for NameConstraints, 
	 * meaning GeneralName with 8 octets for ipv4 and 32 octets for ipv6 addresses.
	 * @throws IllegalArgumentException if the argument does not contain addresses in
	 * the specified format 
	 */
	public void setTargetRestrictionExcludedAddresses(String[] addresses)
			throws IllegalArgumentException
	{
		targetRestrictionExcluded = addresses.clone();
	}
	
	/**
	 * Sets an excluded target IP addressSpace to the data structure.
	 * 
	 * @param addresses The array of 8 element arrays of bytes 
	 * representation of address spaces defined in this structure. 
	 * Each inner 8-elements array must contains IP address and netmask bytes,  
	 * e.g. {137,138,0,0,255,255,0,0}.
	 * @throws IllegalArgumentException when inner arrays are not of length 8
	 * or if does not represent a valid address and netmask combination.
	 */
	public void setTargetRestrictionExcludedAddresses(byte[][] addresses)
			throws IllegalArgumentException
	{
		targetRestrictionExcluded = ProxyAddressRestrictionData.convert2strings(addresses);
	}
	
	/**
	 * Gets an excluded target IP addressSpace from the data structure.
	 * 
	 * @return The array of addresses in the CIDR format (address/netmaskBits)
	 * or null if not set
	 */
	public String[] getTargetRestrictionExcludedAddresses()
	{
		return targetRestrictionExcluded == null ? null :
			targetRestrictionExcluded.clone();
	}

	/**
	 * Sets an excluded from source restriction IP addressSpace to the data structure.
	 *
	 * @param addresses The address space to add to the allowed ip address space. 
	 * Example of the format: 192.168.0.0/16.
	 * It equals a 192.168.0.0 with a net mask 255.255.0.0. 
	 * A single IP address can be defined as xxx.xxx.xxx.xxx/32. <br>
	 * See <a href="http://www.ietf.org/rfc/rfc4632.txt"> RFC 4632.</a> 
	 * The restriction is of the format used for NameConstraints, 
	 * meaning GeneralName with 8 octets for ipv4 and 32 octets for ipv6 addresses.
	 * @throws IllegalArgumentException if the argument does not contain addresses in
	 * the specified format 
	 */
	public void setSourceRestrictionExcludedAddresses(String[] addresses)
			throws IllegalArgumentException
	{
		sourceRestrictionExcluded = addresses.clone();
	}
	
	/**
	 * Sets an excluded from source restriction IP addressSpace to the data structure.
	 * 
	 * @param addresses The array of 8 element arrays of bytes 
	 * representation of address spaces defined in this structure. 
	 * Each inner 8-elements array must contains IP address and netmask bytes,  
	 * e.g. {137,138,0,0,255,255,0,0}.
	 * @throws IllegalArgumentException when inner arrays are not of length 8
	 * or if does not represent a valid address and netmask combination.
	 */
	public void setSourceRestrictionExcludedAddresses(byte[][] addresses)
			throws IllegalArgumentException
	{
		sourceRestrictionExcluded = ProxyAddressRestrictionData.convert2strings(addresses);
	}
	
	/**
	 * Gets an excluded from source restriction IP addressSpace from the data structure.
	 * 
	 * @return The array of addresses in the CIDR format (address/netmaskBits)
	 * or null if not set
	 */
	public String[] getSourceRestrictionExcludedAddresses()
	{
		return sourceRestrictionExcluded == null ? null : 
			sourceRestrictionExcluded.clone();
	}

	
	
	
	
	/**
	 * Sets the issuer URL for the proxy tracing.
	 * 
	 * @param url the issuer URL
	 */
	public void setProxyTracingIssuer(String url)
	{
		this.proxyTracingIssuer = url;
	}
	
	/**
	 * @return Gets the issuer URL for the proxy tracing.
	 */
	public String getProxyTracingIssuer()
	{
		return proxyTracingIssuer;
	}

	/**
	 * Sets the subject URL for the proxy tracing.
	 * @param url the subject URL
	 */
	public void setProxyTracingSubject(String url)
	{
		this.proxyTracingSubject = url;
	}
	
	/**
	 * @return Gets the subject URL for the proxy tracing.
	 */
	public String getProxyTracingSubject()
	{
		return proxyTracingSubject;
	}
	
	/**
	 * Gets SAML assertions in a string format.
	 * @return SAML assertions
	 */
	public String getSAMLAssertion()
	{
		return samlAssertion;
	}
	
	/**
	 * Sets SAML assertions in a string format.
	 * @param saml assertions to be used
	 */
	public void setSAMLAssertion(String saml)
	{
		samlAssertion = saml;
	}
	
	/**
	 * Sets Attribute certificates, which will be added as the VOMS extensions to the generated proxy.
	 * @param ac to be set
	 * @throws IOException 
	 */
	public void setAttributeCertificates(AttributeCertificate[] ac) throws IOException
	{
		attributeCertificates = new AttributeCertificate[ac.length];
		for (int i=0; i<ac.length; i++)
			attributeCertificates[i] = 
				AttributeCertificate.getInstance(ac[i].getEncoded(ASN1Encoding.DER));
	}
	
	/**
	 * 
	 * @return Attribute certificates or null if was not set
	 * @throws IOException 
	 */
	public AttributeCertificate[] getAttributeCertificates() throws IOException
	{
		if (attributeCertificates == null)
			return null; 
		AttributeCertificate[] ret = new AttributeCertificate[attributeCertificates.length];
		for (int i=0; i<attributeCertificates.length; i++)
			ret[i] = AttributeCertificate.getInstance(
					attributeCertificates[i].getEncoded(ASN1Encoding.DER));
		return ret;
	}
}
