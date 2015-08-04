/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 *
 * Derived from the code copyrighted and licensed as follows:
 * 
 * Copyright (c) Members of the EGEE Collaboration. 2004.
 * See http://www.eu-egee.org/partners/ for details on the copyright
 * holders.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *    http://www.apache.org/licenses/LICENSE-2.0
 *    
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package eu.emi.security.authn.x509.helpers.proxy;

import java.io.IOException;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;

import eu.emi.security.authn.x509.helpers.CertificateHelpers;
import eu.emi.security.authn.x509.proxy.ProxyPolicy;

/**
 * Various helpers for handling proxy certificates
 *
 * @author J. Hahkala
 * @author K. Benedyczak
 */
public class ProxyHelper
{
	/**
	 * Checks if the certificate is a proxy and if so return its type.
	 * @param certificate to be checked
	 * @return the proxy type or info that it is a normal certificate.
	 */
	public static ExtendedProxyType getProxyType(X509Certificate certificate)
	{
		if (certificate.getExtensionValue(ProxyCertInfoExtension.RFC_EXTENSION_OID) != null
				&& certificate.getExtensionValue(ProxyCertInfoExtension.RFC_EXTENSION_OID).length > 0)
			return ExtendedProxyType.RFC3820;
		
		if (certificate.getExtensionValue(ProxyCertInfoExtension.DRAFT_EXTENSION_OID) != null
				&& certificate.getExtensionValue(ProxyCertInfoExtension.DRAFT_EXTENSION_OID).length > 0)
			return ExtendedProxyType.DRAFT_RFC;

		String value;
		try
		{
			value = getLastCN(certificate.getSubjectX500Principal());
		} catch (IllegalArgumentException e) //empty subject DN
		{
			value = "";
		}
		
		if ("proxy".equals(value.toLowerCase())
				|| "limited proxy".equals(value.toLowerCase()))
			return ExtendedProxyType.LEGACY;
		return ExtendedProxyType.NOT_A_PROXY;
	}


	public static String getLastCN(X500Principal principal) throws IllegalArgumentException
	{
		X500Name x500Name = CertificateHelpers.toX500Name(principal);
		return getLastCN(x500Name);
	}

	public static String getLastCN(X500Name x500Name) throws IllegalArgumentException
	{
		RDN[] rdns = x500Name.getRDNs();
		if (rdns.length == 0)
			throw new IllegalArgumentException("The DN is empty");
		RDN last = rdns[rdns.length-1];
		
		if (last.isMultiValued())
			throw new IllegalArgumentException("The DN is ended with a multivalued RDN");
		AttributeTypeAndValue cn = last.getFirst();
		if (!cn.getType().equals(BCStyle.CN))
			throw new IllegalArgumentException("The DN is not ended with a CN AVA");

		return IETFUtils.valueToString(cn.getValue());
	}
	
	
	/**
	 * Returns the proxy path limit of the proxy. The argument is not checked if
	 * is a real proxy. 
	 * @param cert certificate
	 * @return path limit as set for the DRAFT and RFC proxies. In case of legacy proxies
	 * or unlimited proxies Integer.MAX_VALUE is returned.
	 * @throws IOException if the extension can not be parsed
	 */
	public static int getProxyPathLimit(X509Certificate cert)
			throws IOException
	{
		ProxyCertInfoExtension info = ProxyCertInfoExtension.getInstance(cert);
		if (info == null)
			return Integer.MAX_VALUE;
		return info.getProxyPathLimit();
	}

	/**
	 * Checks if the certificate is a limited proxy in Globus sense, i.e. if its last CN is equal to 'limited proxy'
	 * (in case of legacy proxies) or if the special limited proxy policy is used.
	 * @param cert certificate
	 * @return true only if the parameter is a limited proxy
	 * @throws IOException IO exception
	 */
	public static boolean isLimited(X509Certificate cert) throws IOException
	{
		ExtendedProxyType type = getProxyType(cert);
		if (type == ExtendedProxyType.RFC3820 || type == ExtendedProxyType.DRAFT_RFC)
		{
			ProxyCertInfoExtension ext = ProxyCertInfoExtension.getInstance(cert);
			ProxyPolicy policy = ext.getPolicy();
			return ProxyPolicy.LIMITED_PROXY_OID.equals(policy.getPolicyOID());
		} else if (type == ExtendedProxyType.LEGACY)
		{
			String cn;
			try
			{
				cn = getLastCN(cert.getSubjectX500Principal());
			} catch (IllegalArgumentException e)
			{
				cn = "";
			}
			return "limited proxy".equals(cn.toLowerCase());
		}
		return false;
	}
}
