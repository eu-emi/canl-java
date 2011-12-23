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

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERSequence;

import eu.emi.security.authn.x509.helpers.CertificateHelpers;
import eu.emi.security.authn.x509.proxy.ProxyPolicy;

/**
 * Proxy cert info extension class.
 * 
 * <pre>
 * ProxyCertInfoExtension ::= SEQUENCE { 
 *          pCPathLenConstraint    ProxyCertPathLengthConstraint OPTIONAL, 
 *          proxyPolicy            ProxyPolicy }
 *  
 *     ProxyCertPathLengthConstraint ::= INTEGER
 * </pre>
 * 
 * @author Joni Hahkala
 * @author K. Benedyczak
 */
public class ProxyCertInfoExtension extends ASN1Encodable
{
	/** The oid of the proxy cert info extension, defined in the RFC 3820. */
	public static final String RFC_EXTENSION_OID = "1.3.6.1.5.5.7.1.14";

	/** The oid of the rfc draft proxy cert extension. */
	public static final String DRAFT_EXTENSION_OID = "1.3.6.1.4.1.3536.1.1.222";

	/**
	 * The sub proxy path length, default is not limited.
	 */
	private int pathLen = Integer.MAX_VALUE;

	/**
	 * The underlying policy object.
	 */
	private ProxyPolicy policy;

	/**
	 * Generate new proxy certificate info extension with length limit len
	 * and policy policy. Use negative value if no limit is desired.
	 * 
	 * @param pathLen
	 *                the maximum number of proxy certificates to follow
	 *                this one. If Integer.MAX_VALUE is used then no limit will be set. 
	 * @param policy
	 *                the proxy policy extension.
	 */
	public ProxyCertInfoExtension(int pathLen, ProxyPolicy policy)
	{
		this.pathLen = pathLen;
		this.policy = policy;
	}

	/**
	 * Generate a proxy that inherits all rights and that has no cert path
	 * length limitations.
	 */
	public ProxyCertInfoExtension()
	{
		policy = new ProxyPolicy(ProxyPolicy.INHERITALL_POLICY_OID);
	}

	/**
	 * Constructor that generates instance out of byte array.
	 * 
	 * @param bytes
	 *                The byte array to consider as the ASN.1 encoded
	 *                proxyCertInfo extension.
	 * @throws IOException
	 *                 thrown in case the parsing of the byte array fails.
	 */
	public ProxyCertInfoExtension(byte[] bytes) throws IOException
	{
		this((ASN1Sequence) ASN1Object.fromByteArray(bytes));
	}

	/**
	 * Read a proxyCertInfoExtension from the ASN1 sequence.
	 * 
	 * @param seq
	 *                The sequence containing the extension.
	 * @throws IOException 
	 */
	public ProxyCertInfoExtension(ASN1Sequence seq) throws IOException
	{
		int index = 0;
		
		if (seq == null || seq.size() == 0)
			throw new IOException("ProxyCertInfoExtension is empty");

		if (seq.getObjectAt(0) instanceof DERInteger)
		{
			pathLen = ((DERInteger) seq.getObjectAt(0)).getValue().intValue();
			index = 1;
		}
		if (seq.size() <= index)
			throw new IOException("ProxyCertInfoExtension parser error, expected policy, but it was not found");
		
		if (seq.getObjectAt(index) instanceof DERSequence)
		{
			policy = new ProxyPolicy((ASN1Sequence)seq.getObjectAt(index));
		} else
		{
			throw new IOException("ProxyCertInfoExtension parser error, expected policy sequence, but got: "
					+ seq.getObjectAt(index).getClass());
		}
		
		index++;
		if (seq.size() > index)
			throw new IOException("ProxyCertInfoExtension parser error, sequence contains too many items");
	}

	
	/**
	 * Tries to generate {@link ProxyCertInfoExtension} object from the 
	 * provided certificate. Returns null if the certificate has no proxy extension
	 * (draft or rfc).
	 * @param cert
	 * @return instance intialized from the certificate object
	 * @throws IOException 
	 */
	public static ProxyCertInfoExtension getInstance(X509Certificate cert) throws IOException
	{
		byte[] bytes = CertificateHelpers.getExtensionBytes(cert,
				ProxyCertInfoExtension.RFC_EXTENSION_OID);

		// if not found, check if there is draft extension
		if (bytes == null)
			bytes = CertificateHelpers.getExtensionBytes(cert,
					ProxyCertInfoExtension.DRAFT_EXTENSION_OID);

		if (bytes == null)
			return null;

		return new ProxyCertInfoExtension(bytes);
	}
	
	/**
	 * Get the proxy certificate path length limit of this extension, if
	 * set.
	 * 
	 * @return The number of allowed proxy certificates in the chain allowed
	 *         after this certificate. Integer.MAX_VALUE if not set.
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

	@Override
	public DERObject toASN1Object()
	{
		ASN1EncodableVector v = new ASN1EncodableVector();
		if (pathLen != Integer.MAX_VALUE)
			v.add(new DERInteger(pathLen));

		if (policy != null)
		{
			v.add(policy.toASN1Object());
		} else
		{
			throw new IllegalArgumentException("Can't generate " +
					"ProxyCertInfoExtension without mandatory policy");
		}
		return new DERSequence(v);
	}
}
