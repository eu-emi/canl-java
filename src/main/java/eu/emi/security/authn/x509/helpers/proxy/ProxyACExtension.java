/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.proxy;

import java.io.IOException;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.x509.AttributeCertificate;

import eu.emi.security.authn.x509.helpers.CertificateHelpers;

/**
 * A class for handling the VOMS AC extension in certificates (OID: 1.3.6.1.4.1.8005.100.100.5)
 * 
 * @author K. Benedyczak
 */
public class ProxyACExtension extends ASN1Object
{
	/** The OID for the AC assertion. */
	public static final String AC_OID = "1.3.6.1.4.1.8005.100.100.5";

	/** The ASN.1 encoded contents of the extension. */
	private DLSequence ac = null;

	/**
	 * Generates a new ProxyACExtension object form the byte array
	 * 
	 * @param bytes bytes
	 * @throws IOException IO exception
	 */
	public ProxyACExtension(byte[] bytes) throws IOException
	{
		ac = (DLSequence) ASN1Primitive.fromByteArray(bytes);
	}

	/**
	 * Used to generate an instance from the AttributeCertificate object.
	 * 
	 * @param certificates the AC
	 */
	public ProxyACExtension(AttributeCertificate[] certificates)
	{
		DLSequence seqac = new DLSequence(certificates);
		DLSequence seqWrapper = new DLSequence(seqac);
		this.ac = seqWrapper;
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
		DLSequence seqac = (DLSequence) ac.getObjectAt(0);
		AttributeCertificate[] ret = new AttributeCertificate[seqac.size()];
		for (int i=0; i<ret.length; i++)
			ret[i] = AttributeCertificate.getInstance(seqac.getObjectAt(i));
		return ret;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public ASN1Primitive toASN1Primitive()
	{
		return ac;
	}
}
