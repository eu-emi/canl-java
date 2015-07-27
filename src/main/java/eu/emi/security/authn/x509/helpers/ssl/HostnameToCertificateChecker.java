/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.ssl;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.regex.Pattern;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.util.IPAddress;

import eu.emi.security.authn.x509.helpers.CertificateHelpers;
import eu.emi.security.authn.x509.impl.CertificateUtils;

/**
 * Verifies if a peer's host name matches a DN of its certificate. It is useful on client side
 * when connecting to a server.
 * <p>
 * By default the implementation checks the certificate's Subject Alternative Name 
 * and Common Name, following the server identity part of RFC 2818. Additionally the
 * 'service/hostname' syntax is supported (the service prefix is simply ignored).
 * <p> 
 * If there is a name mismatch the nameMismatch() method is called. 
 * User of this class must extend it and provide the application specific reaction 
 * in this method.
 * <p>
 * Note that this class should be used only on SSL connections which are
 * authenticated with X.509 certificates.
 * 
 * @author Joni Hahkala
 * @author K. Benedyczak
 */
public class HostnameToCertificateChecker
{
	static 
	{
		CertificateUtils.configureSecProvider();
	}

	protected static class ResultWrapper
	{
		private boolean result = false;
	}
	
	public boolean checkMatching(String hostname, X509Certificate certificate) 
			throws CertificateParsingException, UnknownHostException
	{
		ResultWrapper result = new ResultWrapper();
		if (checkAltNameMatching(result, hostname, certificate))
			return result.result;
		return checkCNMatching(hostname, certificate);
	}
	
	/**
	 * 
	 * @param result result
	 * @param hostname hostname
	 * @param certificate certificate
	 * @return true iff a dNSName in altName was found (not if the matching was successful)
	 * RFC is unclear whether IP AltName presence is also taking the precedence over CN
	 * so we are not enforcing such a rule. 
	 * @throws CertificateParsingException certificate parsing exception
	 * @throws UnknownHostException unknown host exception
	 */
	protected boolean checkAltNameMatching(ResultWrapper result, String hostname, 
			X509Certificate certificate) throws CertificateParsingException, UnknownHostException
	{
		Collection<List<?>> collection = certificate.getSubjectAlternativeNames();
		if (collection == null)
			return false;
		boolean ipAsHostname = IPAddress.isValid(hostname);

		boolean applicable = false;
		Iterator<List<?>> collIter = collection.iterator();
		while (collIter.hasNext())
		{
			List<?> item = collIter.next();
			int type = ((Integer) item.get(0)).intValue();

			if (type == GeneralName.dNSName)
			{
				applicable = true;
				if (!ipAsHostname)
				{
					String dnsName = (String) item.get(1);
					if (matchesDNS(hostname, dnsName))
					{
						result.result = true;
						return applicable;
					}
				}
			} else if (type == GeneralName.iPAddress && ipAsHostname)
			{
				String ipString = (String) item.get(1);
				if (matchesIP(hostname, ipString))
				{
					result.result = true;
					return applicable;
				}
			}
		}
		return applicable;
	}

	/**
	 * 
	 * @return true if a CN was found and the matching was successful ;-)
	 */
	protected boolean checkCNMatching(String hostname, X509Certificate certificate)
	{
		X500Principal principal = certificate.getSubjectX500Principal();
		if ("".equals(principal.getName()))
			return false;

		String cnValue = getMostSpecificCN(principal);
		if (cnValue == null)
			return false;

		int index = cnValue.indexOf('/');
		if (index >= 0)
			cnValue = cnValue.substring(index + 1, cnValue.length());

		return matchesDNS(hostname, cnValue);
	}
	
	public static boolean matchesDNS(String hostname, String pattern)
	{
		String regexp = makeRegexpHostWildcard(pattern);
		Pattern p = Pattern.compile(regexp, Pattern.CASE_INSENSITIVE);
		return p.matcher(hostname).matches();
	}

	/**
	 * Converts hostname wildcard string to Java regexp, ensuring that 
	 * literal sequences are correctly escaped. 
	 * @param pattern hostname wildcard
	 * @return Java regular expression
	 */
	public static String makeRegexpHostWildcard(String pattern)
	{
		String[] rPNames = pattern.split("\\*");
		StringBuilder patternB = new StringBuilder();
		if (pattern.startsWith("*"))
			patternB.append("[^\\.]*");
		for (int i=0; i<rPNames.length; i++)
		{
			patternB.append(Pattern.quote(rPNames[i]));
			if (i+1<rPNames.length)
				patternB.append("[^\\.]*");
		}
		if (pattern.endsWith("*"))
			patternB.append("[^\\.]*");
		return patternB.toString();
	}
	

	protected boolean matchesIP(String what, String pattern) throws UnknownHostException
	{
		byte[] addr1 = InetAddress.getByName(what).getAddress();
		byte[] addr2 = InetAddress.getByName(pattern).getAddress();
		return Arrays.equals(addr1, addr2);
	}
	
	public String getMostSpecificCN(X500Principal srcP)
	{
		X500Name src = CertificateHelpers.toX500Name(srcP);
		RDN[] srcRDNs = src.getRDNs();
		String ret = null;
		for (RDN rdn: srcRDNs)
		{
			if (rdn.isMultiValued())
				continue;
			AttributeTypeAndValue ava = rdn.getFirst();
			if (ava.getType().equals(BCStyle.CN))
				ret = IETFUtils.valueToString(ava.getValue());
		}
		return ret;
	}
}
