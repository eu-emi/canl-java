/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.proxy;

import java.io.IOException;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AttributeCertificate;

import eu.emi.security.authn.x509.helpers.CertificateHelpers;

/**
 * A class for handling the VOMS AC extension in certificates.
 * 
 * @author K. Benedyczak
 */
public class ProxyACExtension extends ASN1Encodable
{
	/** The OID for the AC assertion. */
	public static final String AC_OID = "1.3.6.1.4.1.8005.100.100.5";

	/** The ASN.1 encoded contents of the extension. */
	private DERObject ac = null;

	/**
	 * Generates a new ProxyACExtension object form the byte array
	 * 
	 * @param bytes 
	 * @throws IOException
	 */
	public ProxyACExtension(byte[] bytes) throws IOException
	{
		ac = (DEROctetString) ASN1Object.fromByteArray(bytes);
	}

	/**
	 * Used to generate an instance form the AttributeCertificate object.
	 * 
	 * @param certificate the AC
	 */
	public ProxyACExtension(AttributeCertificate[] certificates)
	{
		DERSequence seqac = new DERSequence(certificates);
		DERSequence seqWrapper = new DERSequence(seqac);
		this.ac = seqWrapper.getDERObject();
	}

	/**
	 * Returns the AC extension form the certificate.
	 * 
	 * @return The AC extension object. In no extension was
	 *         found, null is returned.
	 * @throws IOException
	 *                 In case there is a problem parsing the certificate.
	 */
	public static ProxyACExtension getInstance(X509Certificate cert) throws IOException
	{
		byte bytes[] = CertificateHelpers.getExtensionBytes(cert, ProxyACExtension.AC_OID);

		if (bytes == null || bytes.length == 0)
			return null;

		return new ProxyACExtension(bytes);
	}
	
	/**
	 * Used to get the AC extension object.
	 * 
	 * @return The AC object
	 */
	public AttributeCertificate[] getAttributeCertificates()
	{
		DERSequence seqWrapper = new DERSequence(ac);
		DERSequence seqac = (DERSequence) seqWrapper.getObjectAt(0);
		AttributeCertificate[] ret = new AttributeCertificate[seqac.size()];
		for (int i=0; i<ret.length; i++)
			ret[i] = AttributeCertificate.getInstance(seqac.getObjectAt(i));
		return ret;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public DERObject toASN1Object()
	{
		return ac;
	}
}
