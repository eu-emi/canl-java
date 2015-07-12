/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.proxy;


import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

/**
 * Stores DER form of a certificate extension along with its OID and 
 * flag if the extension is critical. 
 *
 * @author K. Benedyczak
 */
public class CertificateExtension extends OidAndValue<ASN1Object> implements ASN1Encodable
{
	private boolean critical;
	
	public CertificateExtension(String oid, ASN1Object value, 
			boolean critical)
	{
		super(oid, value);
		this.critical = critical;
	}
	
	public CertificateExtension(byte[] encoded)
	{
		ASN1Sequence seq = ASN1Sequence.getInstance(encoded);
		if (seq.size() != 2 && seq.size() != 3)
			throw new IllegalArgumentException("Certificate extension must have 2 or 3 elements");
		ASN1ObjectIdentifier oidId = (ASN1ObjectIdentifier) seq.getObjectAt(0);
		oid = oidId.getId();
		
		if (seq.size() == 2)
		{
			critical = false;
			value = (ASN1Object) seq.getObjectAt(1);
		} else
		{
			ASN1Boolean crit = (ASN1Boolean) seq.getObjectAt(1);
			critical = crit.isTrue();
			value = (ASN1Object) seq.getObjectAt(2);
		}
	}
	
	public boolean isCritical()
	{
		return critical;
	}
	public void setCritical(boolean critical)
	{
		this.critical = critical;
	}

	/**
	 * <pre>
	 *     Extension         ::=   SEQUENCE {
	 *        extnId            EXTENSION.&amp;id ({ExtensionSet}),
	 *        critical          BOOLEAN DEFAULT FALSE,
	 *        extnValue         OCTET STRING }
	 * </pre>
	 */
	@Override
	public ASN1Primitive toASN1Primitive()
	{
		ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(getOid());
		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(oid);
		if (isCritical())
			v.add(ASN1Boolean.getInstance(true));

		v.add(getValue());
		return new DERSequence(v);
	}

}
