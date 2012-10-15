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
import java.io.UnsupportedEncodingException;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DEROctetString;

import eu.emi.security.authn.x509.helpers.CertificateHelpers;

/**
 * A class for handling the SAML extension in the Certificate. OID: 1.3.6.1.4.1.3536.1.1.1.12
 * 
 * @author joni.hahkala@cern.ch
 * @author K. Benedyczak
 */
public class ProxySAMLExtension extends ASN1Encodable
{
	/** The OID for the SAML assertion. */
	public static final String SAML_OID = "1.3.6.1.4.1.3536.1.1.1.12";

	/** The legacy OID for the SAML assertion. Not supported as format 
	 * is flawed. */
	public static final String LEGACY_SAML_OID = "1.3.6.1.4.1.3536.1.1.1.10";

	/** The ASN.1 encoded contents of the extension. */
	private DEROctetString saml = null;

	/**
	 * Generates a new SAMLExtension object form the byte array
	 * 
	 * @param bytes
	 * @throws IOException
	 */
	public ProxySAMLExtension(byte[] bytes) throws IOException
	{
		saml = (DEROctetString) ASN1Object.fromByteArray(bytes);

	}

	/**
	 * Used to generate an instance form the SAML assertion in String
	 * format.
	 * 
	 * @param samlString
	 */
	public ProxySAMLExtension(String samlString)
	{
		try
		{
			this.saml = new DEROctetString(samlString.getBytes("UTF-8"));
		} catch (UnsupportedEncodingException e)
		{
			throw new RuntimeException("UTF-8 encoding is unsupported - JDK problem", e);
		}
	}

	/**
	 * Returns the SAML extension form the certificate.
	 * 
	 * @return The SAML assertion extension object. In no SAML extension was
	 *         found, null is returned.
	 * @throws IOException
	 *                 In case there is a problem parsing the certificate.
	 */
	public static ProxySAMLExtension getInstance(X509Certificate cert) throws IOException
	{
		byte bytes[] = CertificateHelpers.getExtensionBytes(cert, ProxySAMLExtension.SAML_OID);

		if (bytes == null || bytes.length == 0)
			return null;

		return new ProxySAMLExtension(bytes);
	}
	
	/**
	 * Used to get the SAML assertion in String format.
	 * 
	 * @return The SAML sertion in string format.
	 */
	public String getSAML()
	{
		try
		{
			return new String(saml.getOctets(), "UTF-8");
		} catch (UnsupportedEncodingException e)
		{
			throw new RuntimeException("UTF-8 encoding is unsupported - JDK problem", e);
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public DERObject toASN1Object()
	{
		return saml.toASN1Object();
	}
}
