/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.impl;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.IETFUtils;

import eu.emi.security.authn.x509.helpers.CertificateHelpers;
import eu.emi.security.authn.x509.helpers.DNComparator;
import eu.emi.security.authn.x509.helpers.JavaAndBCStyle;

/**
 * Contains utility static methods which are helpful in manipulating X.500 Distinguished
 * Names, especially encoded in String form using RFC 2253.
 *  
 * @author K. Benedyczak
 */
public class X500NameUtils
{
	static 
	{
		CertificateUtils.configureSecProvider();
	}

	/**
	 * Convenience method, based on the standard JDK algorithm for DNs comparison.
	 * However this method is less strict then the original: it compares DC and EMAIL 
	 * attributes in a case insensitive way. Input arguments with values encoded 
	 * in hex are also correctly handled. What is more it supports DNs with attribute 
	 * names normally not recognized by the X500Principial class.
	 * 
	 * @param rfc2253dn1 to be compared (need not to strictly follow the RFC encoding)
	 * @param rfc2253dn2 to be compared (need not to strictly follow the RFC encoding)
	 * @return true if DNs are equivalent
	 * @throws IllegalArgumentException if at least one of the DNs can not be parsed
	 */
	public static boolean equal(String rfc2253dn1, String rfc2253dn2) throws IllegalArgumentException
	{
		//first part: ensures that popular attribute names unsupported by JDK are encoded with OIDs
		//and converts all DC and EMAIL attributes to lower case.
		String rfcA = DNComparator.preNormalize(rfc2253dn1);
		String rfcB = DNComparator.preNormalize(rfc2253dn2);
		
		//Finally compare using CANONICAL forms.
		return new X500Principal(rfcA).equals(new X500Principal(rfcB));
	}

	/**
	 * Convenience method for DN comparison. Is is equivalent to usage of the 
	 * {@link #equal(String, String)}, after retrieving a String representation of 
	 * the first argument. 
	 * @param dn to be compared
	 * @param rfc2253dn2 to be compared
	 * @return true if DNs are equivalent
	 * @throws IllegalArgumentException if the String DN can not be parsed
	 */
	public static boolean equal(X500Principal dn, String rfc2253dn2) throws IllegalArgumentException
	{
		//do it carefully: first loose any ASN.1 info, then compare text versions
		String dn1Str = dn.getName();
		return equal(dn1Str, rfc2253dn2);
	}
	
	/**
	 * Uses the strict RFC 3280 algorithm to compare two DNs. This method should be used 
	 * when both arguments were retrieved directly from the certificate, and therefore possess 
	 * the full type information for the attributes forming the DNs.
	 * <p> 
	 * Note 1: that in certain situations it is possible to get a false answer when 
	 * comparing DNs with this method, while other DN equality tests from this class 
	 * (operating on String DN representations) return true.
	 * <p>
	 * Note 2: it is nearly always wrong to convert a string representation of a DN to the
	 * X500Principal object and then to compare it against another using this method. 
	 * In such a case always use the other equal methods from this class with one or 
	 * two String arguments.
	 * <p>
	 * Note 3: this implementation is actually delegating to the JDK's {@link X500Principal} 
	 * equals method, which seems to follow (one of the versions of) the rules of the RFC.
	 *    
	 * @param dn to be compared
	 * @param dn2 to be compared
	 * @return if DNs are equivalent
	 */
	public static boolean rfc3280Equal(X500Principal dn, X500Principal dn2)
	{
		return dn.equals(dn2);
	}
	
	/**
	 * Returns a human-readable representation of this DN. The output is very similar
	 * to the output of X500Principial.getName() but additional attributes like 
	 * EMAIL are recognized, correctly parsed and are not output as OIDs. 
	 * <p>
	 * Note: it may happen that output of this method won't be parseable by 
	 * the X500Principal constructor.
	 * 
	 * @param srcDn to be output
	 * @return human readable form
	 * @throws IllegalArgumentException if the source DN can not be parsed
	 */
	public static String getReadableForm(String srcDn) throws IllegalArgumentException
	{
		JavaAndBCStyle style = new JavaAndBCStyle();
		X500Name x500Name = new X500Name(style, srcDn);
		return style.toStringFull(x500Name);
	}

	/**
	 * Returns a human-readable representation of this DN. The output is very similar
	 * to the output of X500Principial.toString() but additional attributes like 
	 * EMAIL are recognized and are not output as OIDs. 
	 * <p>
	 * Note: it may happen that output of this method won't be parseable by 
	 * the X500Principal constructor.
	 * @param srcDn to be output
	 * @return human readable form
	 */
	public static String getReadableForm(X500Principal srcDn)
	{
		return getReadableForm(srcDn.getName());
	}
	
	/**
	 * Returns a form of the source DN in RFC 2253 form (or similar - some
	 * minor format violations are properly handled) which is strictly RFC2253
	 * and is guaranteed to be correctly parsed by the JDK methods. 
	 * What is more it should be correctly parsed by other implementations.
	 * However this form can be not human readable.
	 *  
	 * @param srcDn to be reformatted
	 * @return portable, RFC 2253 form
	 */
	public static String getPortableRFC2253Form(String srcDn)
	{
		String preNorm = DNComparator.preNormalize(srcDn);
		return new X500Principal(preNorm).getName();
	}
	
	/**
	 * Returns a form of the source DN in RFC 2253 form  (or similar - some
	 * minor format violations are properly handled) which is suitable for string comparison.
	 * I.e. it is guaranteed that all equivalent DNs will result in the same string. 
	 * This method do not guarantee that always two non equivalent DNs produce a different output:
	 * this can not be guaranteed as there is no information on attribute type in the source DN.
	 * However this is unlikely. 
	 * 
	 * @param srcDn input to be reformatted
	 * @return string-comparable form
	 * @since 1.1.0
	 */
	public static String getComparableForm(String srcDn)
	{
		String preNorm = DNComparator.preNormalize(srcDn);
		return new X500Principal(preNorm).getName(X500Principal.CANONICAL);
	}
	
	/**
	 * Returns an array of values of a provided attribute from the DN. Usually the returned array
	 * contains only a single value. 0-length array is returned if the attribute is not present.
	 * If attribute is present in multiple RDNs all values are returned. 
	 * Note that values which are returned are converted to String. Values which can't 
	 * be string encoded, are returned as HEX string (starting with '#'). Note that it may 
	 * happen that even if you passed a DN with attribute encoded in HEX you will
	 * get its string representation - if it is only possible to retrieve it for the attribute.   
	 *
	 * @param srcDn DN to be parsed in RFC 2253 form
	 * @param attribute to be retrieved. {@link JavaAndBCStyle} class and its parent 
	 * contain useful constants.
	 * @return array of attribute values, decoded
	 * @throws IllegalArgumentException if the provided DN can not be parsed
	 */
	public static String[] getAttributeValues(String srcDn, ASN1ObjectIdentifier attribute) throws IllegalArgumentException
	{
		JavaAndBCStyle style = new JavaAndBCStyle();
		X500Name x500Name = new X500Name(style, srcDn);
		return getAttributeValues(x500Name, attribute);
	}

	/**
	 * Returns an array of values of a provided attribute from the DN. 
	 * See {@link #getAttributeValues(String, ASN1ObjectIdentifier)} for details.
	 *
	 * @param srcDn DN to be parsed in RFC 2253 form
	 * @param attribute to be retrieved {@link JavaAndBCStyle} class and its parent contain
	 *  useful constants.
	 * @return array of attribute values, decoded
	 */
	public static String[] getAttributeValues(X500Principal srcDn, ASN1ObjectIdentifier attribute)
	{
		X500Name dn = CertificateHelpers.toX500Name(srcDn);
		return getAttributeValues(dn, attribute);
	}
	
	private static String[] getAttributeValues(X500Name x500Name, ASN1ObjectIdentifier attribute)
	{
		List<String> ret = new ArrayList<String>();
		RDN[] rdns = x500Name.getRDNs();

		for (RDN rdn: rdns)
		{
			AttributeTypeAndValue[] atvs = rdn.getTypesAndValues();
			for (AttributeTypeAndValue atv: atvs)
			{
				if (atv.getType().equals(attribute))
					ret.add(IETFUtils.valueToString(atv.getValue()));
			}
		}
		return ret.toArray(new String[ret.size()]);
	}
	
	/**
	 * Returns a set with all attribute identifiers which are present in the passed DN.
	 * @param srcDn DN to be examined
	 * @return array of all attribute ids
	 */
	public static Set<ASN1ObjectIdentifier> getAttributeNames(String srcDn)
	{
		JavaAndBCStyle style = new JavaAndBCStyle();
		X500Name x500Name = new X500Name(style, srcDn);
		return getAttributeNames(x500Name);
	}
	
	/**
	 * Returns a set with all attribute identifiers which are present in the passed DN.
	 * @param srcDn DN to be examined
	 * @return array of all attribute ids
	 */
	public static Set<ASN1ObjectIdentifier> getAttributeNames(X500Principal srcDn)
	{
		X500Name dn = CertificateHelpers.toX500Name(srcDn);
		return getAttributeNames(dn);
	}

	private static Set<ASN1ObjectIdentifier> getAttributeNames(X500Name dn)
	{
		RDN[] rdns = dn.getRDNs();
		Set<ASN1ObjectIdentifier> ret = new HashSet<ASN1ObjectIdentifier>();
		
		for (RDN rdn: rdns)
		{
			for (AttributeTypeAndValue ava: rdn.getTypesAndValues())
				ret.add(ava.getType());
		}
		return ret;
	}
	
	/**
	 * Constructs a {@link X500Principal} object from a RFC 2253 string. This
	 * method can handle DNs with attributes not supported by the {@link X500Principal}
	 * constructor.    
	 * @param rfcDn RFC 2253 DN
	 * @return the created object
	 * @throws IOException IO exception
	 */
	public static X500Principal getX500Principal(String rfcDn) throws IOException
	{
		JavaAndBCStyle style = new JavaAndBCStyle();
		X500Name x500Name = new X500Name(style, rfcDn);
		RDN[] rdns = x500Name.getRDNs();
		for (int i=0; i<rdns.length/2; i++)
		{
			RDN bak = rdns[i];
			rdns[i] = rdns[rdns.length-1-i];
			rdns[rdns.length-1-i] = bak;
		}
		X500Name x500Name2 = new X500Name(rdns);
		byte []encoded = x500Name2.getEncoded(ASN1Encoding.DER);
		return new X500Principal(encoded);
	}
}
