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
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTaggedObject;
import org.bouncycastle.asn1.DLSequence;

import eu.emi.security.authn.x509.proxy.BaseProxyCertificateOptions;
import eu.emi.security.authn.x509.proxy.ProxyPolicy;

/**
 * Proxy cert info extension class.
 * 
 * <pre>
 * ProxyCertInfoExtension ::= SEQUENCE { 
 *          proxyPolicy            ProxyPolicy,
 *          pCPathLenConstraint    [1] EXPLICIT ProxyCertPathLengthConstraint OPTIONAL }
 *  
 *     ProxyCertPathLengthConstraint ::= INTEGER
 * </pre>
 * 
 * @author Joni Hahkala
 * @author K. Benedyczak
 */
public class DraftRFCProxyCertInfoExtension extends ProxyCertInfoExtension
{
	/** The oid of the rfc draft proxy cert extension. */
	public static final String DRAFT_EXTENSION_OID = "1.3.6.1.4.1.3536.1.222";

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
	public DraftRFCProxyCertInfoExtension(int pathLen, ProxyPolicy policy)
	{
		this.pathLen = pathLen;
		this.policy = policy;
	}

	/**
	 * Generate a proxy that inherits all rights and that has no cert path
	 * length limitations.
	 */
	public DraftRFCProxyCertInfoExtension()
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
	public DraftRFCProxyCertInfoExtension(byte[] bytes) throws IOException
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
	public DraftRFCProxyCertInfoExtension(ASN1Sequence seq) throws IOException
	{
		int index = 0;
		
		if (seq == null || seq.size() == 0)
			throw new IOException("ProxyCertInfoExtension is empty");

		if (seq.getObjectAt(index) instanceof DLSequence)
		{
			policy = new ProxyPolicy((DLSequence)seq.getObjectAt(index));
			index++;
		} else
		{
			throw new IOException("ProxyCertInfoExtension parser error, expected policy sequence, but got: "
					+ seq.getObjectAt(index).getClass());
		}

		if (seq.size() <= index)
			return;

		if (seq.getObjectAt(index) instanceof ASN1TaggedObject)
		{
			ASN1TaggedObject tagged = (ASN1TaggedObject) seq.getObjectAt(index);
			if (tagged.getTagNo() != 1)
				throw new IOException("ProxyCertInfoExtension parser error, "
						+ "expected path constraint tagged with 1 but was tagged with " + 
						tagged.getTagNo());
			ASN1Object pathLenObj = tagged.getExplicitBaseObject();
			if (pathLenObj instanceof ASN1Integer)
				pathLen = ((ASN1Integer) pathLenObj).getValue().intValue();
			else
				throw new IOException("ProxyCertInfoExtension parser error, "
						+ "expected path constraint of integer type but got " + 
						pathLenObj);
		} else
		{
			throw new IOException("ProxyCertInfoExtension parser error, "
					+ "expected path constraint encoded as tagged integer but but got " + 
					seq.getObjectAt(index));
		}
		
		index++;
		if (seq.size() > index)
			throw new IOException("ProxyCertInfoExtension parser error, sequence contains too many items");
	}

	@Override
	public ASN1Primitive toASN1Primitive()
	{
		ASN1EncodableVector v = new ASN1EncodableVector();
		if (policy != null)
		{
			v.add(policy.toASN1Primitive());
		} else
		{
			throw new IllegalArgumentException("Can't generate " +
					"ProxyCertInfoExtension without mandatory policy");
		}
		if (pathLen != BaseProxyCertificateOptions.UNLIMITED_PROXY_LENGTH)
		{
			v.add(new BERTaggedObject(true, 1, new ASN1Integer(pathLen)));
		}

		return new DLSequence(v);
	}
}
