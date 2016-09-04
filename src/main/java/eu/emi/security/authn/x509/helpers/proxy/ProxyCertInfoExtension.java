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

import org.bouncycastle.asn1.ASN1Object;

import eu.emi.security.authn.x509.helpers.CertificateHelpers;
import eu.emi.security.authn.x509.proxy.BaseProxyCertificateOptions;
import eu.emi.security.authn.x509.proxy.ProxyPolicy;

/**
 * Proxy cert info extension class. Defines the common contract, there are two implementations
 * {@link DraftRFCProxyCertInfoExtension} and {@link RFCProxyCertInfoExtension} as the ASN syntax is 
 * different for both types of proxies.
 * 
 * @author K. Benedyczak
 */
public abstract class ProxyCertInfoExtension extends ASN1Object
{
	/**
	 * The sub proxy path length, default is not limited.
	 */
	protected int pathLen = BaseProxyCertificateOptions.UNLIMITED_PROXY_LENGTH;

	/**
	 * The underlying policy object.
	 */
	protected ProxyPolicy policy;

	/**
	 * Tries to generate {@link ProxyCertInfoExtension} object from the 
	 * provided certificate. Returns null if the certificate has no proxy extension
	 * (draft or rfc).
	 * @param cert certificate
	 * @return instance intialized from the certificate object
	 * @throws IOException IO exception
	 */
	public static ProxyCertInfoExtension getInstance(X509Certificate cert) throws IOException
	{
		byte[] bytes = CertificateHelpers.getExtensionBytes(cert,
				RFCProxyCertInfoExtension.RFC_EXTENSION_OID);

		if (bytes != null)
		{
			return new RFCProxyCertInfoExtension(bytes);
		} else
		{
			// if not found, check if there is draft extension
			bytes = CertificateHelpers.getExtensionBytes(cert,
					DraftRFCProxyCertInfoExtension.DRAFT_EXTENSION_OID);
			if (bytes == null)
				return null;

			return new DraftRFCProxyCertInfoExtension(bytes);
		}
	}
	
	/**
	 * Get the proxy certificate path length limit of this extension, if
	 * set.
	 * 
	 * @return The number of allowed proxy certificates in the chain allowed
	 *         after this certificate. -1 if not set.
	 */
	public int getProxyPathLimit()
	{
		return pathLen;
	}

	/**
	 * Get the policy object of this extension.
	 * 
	 * @return The ProxyPolicy object.
	 */
	public ProxyPolicy getPolicy()
	{
		return policy;
	}
}
