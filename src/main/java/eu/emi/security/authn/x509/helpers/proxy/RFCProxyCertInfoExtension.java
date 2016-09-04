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

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DLSequence;

import eu.emi.security.authn.x509.proxy.BaseProxyCertificateOptions;
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
public class RFCProxyCertInfoExtension extends ProxyCertInfoExtension
{
	/** The oid of the proxy cert info extension, defined in the RFC 3820. */
	public static final String RFC_EXTENSION_OID = "1.3.6.1.5.5.7.1.14";

	/**
	 * Generate new proxy certificate info extension with length limit len
	 * and policy policy. Use negative value if no limit is desired.
	 * 
	 * @param pathLen
	 *                the maximum number of proxy certificates to follow
	 *                this one. If -1 is used then no limit will be set. 
	 * @param policy
	 *                the proxy policy extension.
	 */
	public RFCProxyCertInfoExtension(int pathLen, ProxyPolicy policy)
	{
		this.pathLen = pathLen;
		this.policy = policy;
	}

	/**
	 * Generate a proxy that inherits all rights and that has no cert path
	 * length limitations.
	 */
	public RFCProxyCertInfoExtension()
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
	public RFCProxyCertInfoExtension(byte[] bytes) throws IOException
	{
		this((ASN1Sequence) ASN1Primitive.fromByteArray(bytes));
	}

	/**
	 * Read a proxyCertInfoExtension from the ASN1 sequence.
	 * 
	 * @param seq
	 *                The sequence containing the extension.
	 * @throws IOException IO exception
	 */
	public RFCProxyCertInfoExtension(ASN1Sequence seq) throws IOException
	{
		int index = 0;
		
		if (seq == null || seq.size() == 0)
			throw new IOException("ProxyCertInfoExtension is empty");

		if (seq.getObjectAt(index) instanceof ASN1Integer)
		{
			pathLen = ((ASN1Integer) seq.getObjectAt(index)).getValue().intValue();
			index++;
		}
		if (seq.size() <= index)
			throw new IOException("ProxyCertInfoExtension parser error, expected policy, but it was not found");
		
		if (seq.getObjectAt(index) instanceof DLSequence)
		{
			policy = new ProxyPolicy((DLSequence)seq.getObjectAt(index));
		} else
		{
			throw new IOException("ProxyCertInfoExtension parser error, expected policy sequence, but got: "
					+ seq.getObjectAt(index).getClass());
		}
		
		index++;
		if (seq.size() > index)
			throw new IOException("ProxyCertInfoExtension parser error, sequence contains too many items");
	}

	@Override
	public ASN1Primitive toASN1Primitive()
	{
		ASN1EncodableVector v = new ASN1EncodableVector();
		if (pathLen != BaseProxyCertificateOptions.UNLIMITED_PROXY_LENGTH)
			v.add(new ASN1Integer(pathLen));

		if (policy != null)
		{
			v.add(policy.toASN1Primitive());
		} else
		{
			throw new IllegalArgumentException("Can't generate " +
					"ProxyCertInfoExtension without mandatory policy");
		}
		return new DLSequence(v);
	}
}
