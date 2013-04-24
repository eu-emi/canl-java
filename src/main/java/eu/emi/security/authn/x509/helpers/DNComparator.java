/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.helpers;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;

import eu.emi.security.authn.x509.impl.X500NameUtils;

/**
 * Helpers for checking text representations of DNs for equality.
 * 
 * @author K. Benedyczak
 */
public class DNComparator
{
	/**
	 * Returns a form of the original DN which will be properly parsed by JDK {@link X500Principal} class by
	 * replacing attribute names unknown by the {@link X500Principal} with OIDs.
	 * What is more all DC and EMAIL values are converted to lower case.
	 * @param dn in RFC 2253 form.
	 * @return dn in RFC 2253 form, reformatted.
	 */
	public static String preNormalize(String dn)
	{
		RDN[] rdns;
		try 
		{
			rdns = IETFUtils.rDNsFromString(dn, JavaAndBCStyle.INSTANCE);
		} catch (IllegalArgumentException e)
		{
			//let's fail quietly - maybe JDK will do ar will fail too and report its error.
			return dn;
		}
		X500NameBuilder builder = new X500NameBuilder(JavaAndBCStyle.INSTANCE);
		
		for (RDN rdn: rdns)
		{
			if (rdn.isMultiValued())
			{
				AttributeTypeAndValue avas[] = rdn.getTypesAndValues();
				for (int j=0; j<avas.length; j++)
					avas[j] = normalizeAVA(avas[j]);
				builder.addMultiValuedRDN(avas);
			} else
			{
				AttributeTypeAndValue ava = rdn.getFirst();
				builder.addRDN(normalizeAVA(ava));
			}
		}
		return JavaAndBCStyle.INSTANCE.toString(builder.build());
	}

	/**
	 * 
	 * @param dn source dn
	 * @return hashcode useful as a return value of the hshCode() method,
	 * when equals is overriden to use {@link X500NameUtils} equals method.
	 */
	public static int getHashCode(String dn)
	{
		String norm = preNormalize(dn);
		return new X500Principal(norm).hashCode();
	}
	
	/**
	 * Uppers the case of the arg, then lowers it, using non-locale specific 
	 * algorithm.
	 * @param src
	 * @return
	 */
	private static String upLowCase(String src) 
	{
		char[] chars = src.toCharArray();
		StringBuilder ret = new StringBuilder(chars.length);
		for (char c: chars) 
			ret.append(Character.toLowerCase(Character.toUpperCase(c)));
		return ret.toString();
	}
	
	private static AttributeTypeAndValue normalizeAVA(AttributeTypeAndValue orig)
	{
		if (orig.getType().equals(BCStyle.DC) || 
				orig.getType().equals(BCStyle.EmailAddress))
		{
			ASN1Encodable value = orig.getValue();
			if (value instanceof ASN1String)
			{
				ASN1String ia5Str = (ASN1String) value;
				String newValue = upLowCase(ia5Str.getString());
				return new AttributeTypeAndValue(orig.getType(), 
					new DERIA5String(newValue));
			} else
			{
				//really shouldn't happen
				throw new IllegalStateException("AVA value not a string");
				//return orig;
			}
		} else
			return orig;
		
	}
}
