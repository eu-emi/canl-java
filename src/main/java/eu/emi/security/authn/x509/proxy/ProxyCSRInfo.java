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
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.PKCS10CertificationRequest;

import eu.emi.security.authn.x509.helpers.JavaAndBCStyle;
import eu.emi.security.authn.x509.helpers.proxy.ProxyAddressRestrictionData;
import eu.emi.security.authn.x509.helpers.proxy.ProxyCertInfoExtension;
import eu.emi.security.authn.x509.helpers.proxy.ProxyHelper;
import eu.emi.security.authn.x509.helpers.proxy.ProxySAMLExtension;
import eu.emi.security.authn.x509.helpers.proxy.ProxyTracingExtension;
import eu.emi.security.authn.x509.impl.CertificateUtils;

/**
 * A class to get the information from the proxy certificate request.
 * 
 * @author J. Hahkala
 * @author K. Benedyczak
 */
public class ProxyCSRInfo 
{
	static 
	{
		CertificateUtils.configureSecProvider();
	}

	private PKCS10CertificationRequest csr;
	
	private List<CertificateExtension> extensions = new ArrayList<CertificateExtension>();
	private String samlAssertion;
	private ProxyCertInfoExtension proxyExt;
	private String proxyExtOid;
	private String tracingSubject;
	private String tracingIssuer;
	private String[][] sourceRestrictions;
	private String[][] targetRestrictions;

	/**
	 * Generates new instance of this class using the Certificate Signing Request
	 * @param csr certificate signing request 
	 * @throws CertificateException if the Certificate Signing Request is invalid
	 */
	public ProxyCSRInfo(PKCS10CertificationRequest csr) throws CertificateException 
	{
		this.csr = csr;
		try
		{
			parseRequestedExtensions();
		} catch (IOException e)
		{
			throw new CertificateException("The CSR can not be parsed as a Proxy CSR", e);
		}
	}

	/**
	 * The type of the proxy certificate requested is returned or null if can not be determined. In principle
	 * the null response means that the DN is not a valid LEGACY proxy DN, and that either RFC or DRAFT 
	 * proxy should be generated.
	 * @return the proxy type
	 */
	public ProxyType getProxyType() 
	{
		if (proxyExtOid != null && proxyExtOid.equals(ProxyCertInfoExtension.RFC_EXTENSION_OID))
			return ProxyType.RFC3820;
		if (proxyExtOid != null && proxyExtOid.equals(ProxyCertInfoExtension.DRAFT_EXTENSION_OID))
			return ProxyType.DRAFT_RFC;
		
		String value;
		try 
		{
			value = getLastCN();
		} catch (IllegalArgumentException e) //empty or wrong subject
		{
			value = "";
		}
		if ("proxy".equals(value.toLowerCase())
				|| "limited proxy".equals(value.toLowerCase()))
			return ProxyType.LEGACY;
		return null;
	}

	private String getLastCN() throws IllegalArgumentException
	{
		byte[] subject = csr.getCertificationRequestInfo().getSubject().getDEREncoded();
		X500Name withDefaultStyle = X500Name.getInstance(subject);
		JavaAndBCStyle style = new JavaAndBCStyle();
		return ProxyHelper.getLastCN(new X500Name(style, withDefaultStyle));
	}
	
	/**
	 * Used to check whether the Certificate Signing Request is for a limited proxy or not.
	 * @return null if not set
	 */
	public Boolean isLimited() 
	{
		ProxyPolicy policy = getPolicy();
		if (policy != null)
		{
			return ProxyPolicy.LIMITED_PROXY_OID.equals(policy.getPolicyOID());
		} else 
		{
			String value;
			try
			{
				value = getLastCN();
			} catch (IllegalArgumentException e) //empty or wrong subject
			{
				value = "";
			}
			if (value.toLowerCase().equals("proxy"))
				return false;
			else if ("limited proxy".equals(value.toLowerCase()))
				return true;
			return null;
		}
	}

	/**
	 * Gets the requested RFC proxy extension policy OID and octets of the
	 * policy. See RFC3820. Policy can be null in case the OID in it self
	 * defines the behavior, like with "inherit all" policy or
	 * "independent" policy.
	 * @return the requested policy or null if not set 
	 */
	public ProxyPolicy getPolicy()
	{
		if (proxyExt == null)
			return null;
		return proxyExt.getPolicy();
	}

	/**
	 * Returns an requested URL of the proxy tracing issuer.
	 * 
	 * @return The proxy tracing issuer URL in String format, 
	 * or null if was not requested.
	 */
	public String getProxyTracingIssuer() 
	{
		return tracingIssuer; 
	}

	/**
	 * Returns a requested URL of the proxy tracing subject.
	 * @return The proxy tracing subject URL in String format, 
	 * or null if was not requested.
	 */
	public String getProxyTracingSubject()
	{
		return tracingSubject;
	}

	/**
	 * Returns the SAML extension from the certificate chain.
	 * 
	 * @return The SAML assertion in String format or null if not set
	 */
	public String getSAMLExtension()
	{
		return samlAssertion;
	}

	/**
	 * Returns the proxy path length limit set in the Certificate Signing Request.
	 * Returns an Integer.MAX_VALUE value if length is set to be unlimited.
	 * @return the requested proxy path length.
	 */
	public Integer getProxyPathLimit()
	{
		if (proxyExt == null)
			return Integer.MAX_VALUE;
		return proxyExt.getProxyPathLimit();
	}

	/**
	 * Gets the proxy source restriction data from the Certificate Signing Request. 
	 * The returned array has as the first item the array of allowed namespaces 
	 * and as the second item the array of excluded namespaces.
	 * @return null if the extension was not set 
	 */
	public String[][] getProxySourceRestrictions()
	{
		return sourceRestrictions;
	}

	/**
	 * Gets the proxy target restriction data from the Certificate Signing Request. 
	 * The returned array has as the first item the array of allowed namespaces 
	 * and as the second item the array of excluded namespaces. 
	 * @return null if the extension was not set 
	 */
	public String[][] getProxyTargetRestrictions()
	{
		return targetRestrictions;
	}
	
	
	private void parseRequestedExtensions() throws IOException
	{
		ASN1Set attrs = csr.getCertificationRequestInfo().getAttributes();
		if (attrs == null)
			return;
		Enumeration<?> enumer = attrs.getObjects();
		while (enumer.hasMoreElements())
		{
			Object raw = enumer.nextElement();
			Attribute a = Attribute.getInstance(raw);
			if (PKCSObjectIdentifiers.pkcs_9_at_extensionRequest.getId().equals(
					a.getAttrType().getId()))
			{
				if (a.getAttrValues().size() == 0)
					continue;
				DEREncodable req = a.getAttrValues().getObjectAt(0);
				CertificateExtension ext = new CertificateExtension(req.getDERObject().getDEREncoded());
				handleRequestedExtension(ext);
			}
		}
	}
	
	private void handleRequestedExtension(CertificateExtension ext) throws IOException
	{
		String oid = ext.getOid();
		byte[] val = ext.getValue().getDERObject().getDEREncoded();
		if (oid.equals(ProxyCertInfoExtension.DRAFT_EXTENSION_OID) || 
				oid.equals(ProxyCertInfoExtension.RFC_EXTENSION_OID))
		{
			proxyExtOid = oid;
			proxyExt = new ProxyCertInfoExtension(val);
		} else if (oid.equals(ProxySAMLExtension.LEGACY_SAML_OID) || 
				oid.equals(ProxySAMLExtension.SAML_OID))
		{
			samlAssertion = new ProxySAMLExtension(val).getSAML();
		} else if (oid.equals(ProxyTracingExtension.PROXY_TRACING_ISSUER_EXTENSION_OID))
		{
			tracingIssuer = new ProxyTracingExtension(val).getURL();
		} else if (oid.equals(ProxyTracingExtension.PROXY_TRACING_SUBJECT_EXTENSION_OID))
		{
			tracingSubject = new ProxyTracingExtension(val).getURL();
		} else if (oid.equals(ProxyAddressRestrictionData.SOURCE_RESTRICTION_OID))
		{
			sourceRestrictions = new String[2][];
			sourceRestrictions[0] = new ProxyAddressRestrictionData(val).getPermittedAddresses();
			sourceRestrictions[1] = new ProxyAddressRestrictionData(val).getExcludedAddresses();
		} else if (oid.equals(ProxyAddressRestrictionData.TARGET_RESTRICTION_OID))
		{
			targetRestrictions = new String[2][];
			targetRestrictions[0] = new ProxyAddressRestrictionData(val).getPermittedAddresses();
			targetRestrictions[1] = new ProxyAddressRestrictionData(val).getExcludedAddresses();
		} else
		{
			extensions.add(ext);
		}
	}
}
