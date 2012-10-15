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

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.asn1.x509.AttributeCertificate;

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

	public static final int DEFAULT_LIFETIME = 12*3600;
	private final X509Certificate[] parentChain;
	
	private int lifetime = DEFAULT_LIFETIME;
	private ProxyType type = ProxyType.RFC3820;
	private boolean limited = false;
	private BigInteger serialNumber = null;
	private int proxyPathLimit = -1;
	
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
	 * @param parentCertChain chain of the issuer
	 */
	protected BaseProxyCertificateOptions(X509Certificate[] parentCertChain)
	{
		if (parentCertChain == null || parentCertChain.length == 0)
			throw new IllegalArgumentException("parent certificate chain must be set");
		this.parentChain = Arrays.copyOf(parentCertChain, parentCertChain.length);
		extensions = new ArrayList<CertificateExtension>();
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
	 * Set the proxy lifetime in seconds. If not set, the default is 12h.
	 * @param lifetime in seconds
	 */
	public void setLifetime(int lifetime)
	{
		this.lifetime = lifetime;
	}

	/**
	 * 
	 * @return proxy lifetime
	 */
	public int getLifetime()
	{
		return lifetime;
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
	 * @param limited true if proxy shall be limited
	 */
	public void setLimited(boolean limited)
	{
		this.limited = limited;
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
	 */
	public void setAttributeCertificates(AttributeCertificate[] ac)
	{
		attributeCertificates = new AttributeCertificate[ac.length];
		for (int i=0; i<ac.length; i++)
			attributeCertificates[i] = 
				AttributeCertificate.getInstance(ac[i].getDEREncoded());
	}
	
	/**
	 * 
	 * @return Attribute certificates or null if was not set
	 */
	public AttributeCertificate[] getAttributeCertificates()
	{
		if (attributeCertificates == null)
			return null; 
		AttributeCertificate[] ret = new AttributeCertificate[attributeCertificates.length];
		for (int i=0; i<attributeCertificates.length; i++)
			ret[i] = AttributeCertificate.getInstance(
					attributeCertificates[i].getDEREncoded());
		return ret;
	}
}
