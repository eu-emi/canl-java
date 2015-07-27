/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.helpers;

import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.util.Strings;

/**
 * Extends {@link BCStyle} with additional recognized attribute names, to make
 * it fully compatible with what the internal OpenJDK implementation supports
 * when parsing string RFC 2253 DNs.
 * <p>
 * The serialization part of this class (toString(X500Name)) behaves in a
 * different way: it only outputs labels for the attribute names which are
 * recognized by JDK. All other are output as OIDs.
 * <p>
 * Therefore this class allows to consume even unsupported by the JDK DNs, all
 * supported and convert them to BC RDNs form. On the other hand it allows to
 * convert RDNs to RFC 2253 form ensuring that this form is acceptable by the
 * JDK {@link X500Principal} class.
 * 
 * @author K. Benedyczak
 */
public class JavaAndBCStyle extends BCStyle
{
	/**
	 * Mappings which are supported by JDK
	 */
	private static final Map<String, ASN1ObjectIdentifier> string2Asn = new HashMap<String, ASN1ObjectIdentifier>();
	
	/**
	 * Only mappings which are supported by the JDK impl (see sun.security.x509.AVA class).
	 */
	private static final Hashtable<ASN1ObjectIdentifier, String> asn2String = new Hashtable<ASN1ObjectIdentifier, String>();

	/**
	 * All mappings which are supported by the JDK impl (see sun.security.x509.AVA class).
	 * and the BCStyle.
	 */
	public static final Hashtable<ASN1ObjectIdentifier, String> asn2StringAll = new Hashtable<ASN1ObjectIdentifier, String>();

	public static final ASN1ObjectIdentifier IP = new ASN1ObjectIdentifier(
			"1.3.6.1.4.1.42.2.11.2.1");

	public static final JavaAndBCStyle INSTANCE = new JavaAndBCStyle();

	static
	{
		string2Asn.put("email", BCStyle.EmailAddress);
		string2Asn.put("s", BCStyle.ST);
		string2Asn.put("dnqualifier", BCStyle.DN_QUALIFIER);
		string2Asn.put("dnq", BCStyle.DN_QUALIFIER);
		string2Asn.put("ip", IP);

		asn2String.put(CN, "CN");
		asn2String.put(C, "C");
		asn2String.put(L, "L");
		asn2String.put(ST, "ST");
		asn2String.put(O, "O");
		asn2String.put(OU, "OU");
		asn2String.put(T, "T");
		asn2String.put(IP, "IP");
		asn2String.put(STREET, "STREET");
		asn2String.put(DC, "DC");
		asn2String.put(DN_QUALIFIER, "DNQUALIFIER");
		asn2String.put(SURNAME, "SURNAME");
		asn2String.put(GIVENNAME, "GIVENNAME");
		asn2String.put(INITIALS, "INITIALS");
		asn2String.put(GENERATION, "GENERATION");
		asn2String.put(E, "EMAILADDRESS");
		asn2String.put(UID, "UID");
		asn2String.put(SERIALNUMBER, "SERIALNUMBER");
		
	        asn2StringAll.putAll(asn2String);
	        asn2StringAll.put(UnstructuredAddress, "unstructuredAddress");
	        asn2StringAll.put(UnstructuredName, "unstructuredName");
	        asn2StringAll.put(UNIQUE_IDENTIFIER, "UniqueIdentifier");
	        asn2StringAll.put(DN_QUALIFIER, "DN");
	        asn2StringAll.put(PSEUDONYM, "Pseudonym");
	        asn2StringAll.put(POSTAL_ADDRESS, "PostalAddress");
	        asn2StringAll.put(NAME_AT_BIRTH, "NameAtBirth");
	        asn2StringAll.put(COUNTRY_OF_CITIZENSHIP, "CountryOfCitizenship");
	        asn2StringAll.put(COUNTRY_OF_RESIDENCE, "CountryOfResidence");
	        asn2StringAll.put(GENDER, "Gender");
	        asn2StringAll.put(PLACE_OF_BIRTH, "PlaceOfBirth");
	        asn2StringAll.put(DATE_OF_BIRTH, "DateOfBirth");
	        asn2StringAll.put(POSTAL_CODE, "PostalCode");
	        asn2StringAll.put(BUSINESS_CATEGORY, "BusinessCategory");
	        asn2StringAll.put(TELEPHONE_NUMBER, "TelephoneNumber");
	        asn2StringAll.put(NAME, "Name");
	}

	@Override
	public ASN1ObjectIdentifier attrNameToOID(String attrName)
	{
		ASN1ObjectIdentifier asn = string2Asn.get(Strings.toLowerCase(attrName));
		if (asn != null)
			return asn;
		return super.attrNameToOID(attrName);
	}

	/*
	 * Unfortunately we have to copy this whole method, as it hard-coded usage of the static constant.  
	 */
	public String toString(X500Name name, Hashtable<ASN1ObjectIdentifier, String> mappings)
	{
		StringBuffer buf = new StringBuffer();
		boolean first = true;

		RDN[] rdns = name.getRDNs();

		for (int i = 0; i < rdns.length; i++)
		{
			if (first)
			{
				first = false;
			} else
			{
				buf.append(',');
			}

			if (rdns[i].isMultiValued())
			{
				AttributeTypeAndValue[] atv = rdns[i].getTypesAndValues();
				boolean firstAtv = true;

				for (int j = 0; j != atv.length; j++)
				{
					if (firstAtv)
					{
						firstAtv = false;
					} else
					{
						buf.append('+');
					}

					IETFUtils.appendTypeAndValue(buf, atv[j], mappings);
				}
			} else
			{
				IETFUtils.appendTypeAndValue(buf, rdns[i].getFirst(),
						mappings);
			}
		}

		return buf.toString();
	}

	@Override
	public RDN[] fromString(String dirName)
	{
		if ("".equals(dirName))
			return new RDN[0];
		return super.fromString(dirName);
	}

	
	/**
	 * 
	 * @param name name
	 * @return String representation with human readable labels for all attributes known by the JDK.
	 */
	@Override
	public String toString(X500Name name)
	{
		return toString(name, asn2String);
	}

	/**
	 * 
	 * @param name name
	 * @return String representation with human readable labels for all known attributes.
	 */
	public String toStringFull(X500Name name)
	{
		return toString(name, asn2StringAll);
	}
	
	/**
	 * 
	 * @param oid oid
	 * @return String label for the oid if it is known by the JDK
	 */
	public String getLabelForOid(ASN1ObjectIdentifier oid)
	{
		return asn2String.get(oid);
	}

	/**
	 * 
	 * @param oid oid
	 * @return String label for the oid if it is among all known attributes
	 */
	public String getLabelForOidFull(ASN1ObjectIdentifier oid)
	{
		return asn2StringAll.get(oid);
	}
}
