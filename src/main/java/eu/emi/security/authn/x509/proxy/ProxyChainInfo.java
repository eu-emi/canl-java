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
package eu.emi.security.authn.x509.proxy;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.x509.AttributeCertificate;

import eu.emi.security.authn.x509.helpers.proxy.ExtendedProxyType;
import eu.emi.security.authn.x509.helpers.proxy.IPAddressHelper;
import eu.emi.security.authn.x509.helpers.proxy.ProxyACExtension;
import eu.emi.security.authn.x509.helpers.proxy.ProxyAddressRestrictionData;
import eu.emi.security.authn.x509.helpers.proxy.ProxyCertInfoExtension;
import eu.emi.security.authn.x509.helpers.proxy.ProxyHelper;
import eu.emi.security.authn.x509.helpers.proxy.ProxySAMLExtension;
import eu.emi.security.authn.x509.helpers.proxy.ProxyTracingExtension;
import eu.emi.security.authn.x509.impl.CertificateUtils;

/**
 * A class to get an information from a proxy certificate chain.
 *
 * @author J. Hahkala
 * @author K. Benedyczak
 */
public class ProxyChainInfo 
{
	static 
	{
		CertificateUtils.configureSecProvider();
	}

	private X509Certificate[] chain;
	private int firstProxy;
	private ProxyChainType type;
	private ProxyPolicy[] policy;
	private Boolean limited;
	
	/**
	 * Generates new instance of this class using the certificate chain as the source 
	 * of the data.
	 * @param chain chain with at least one proxy certificate
	 * @throws CertificateException if there is no proxy certificate in the chain or
	 * if the chain is inconsistent, i.e. after proxy there is a non-proxy certificate.
	 */
	public ProxyChainInfo(X509Certificate[] chain) throws CertificateException
	{
		if (chain == null || chain.length == 0)
			throw new IllegalArgumentException("Certificate chain passed may not be null or empty");
		int i;
		for (i=chain.length-1; i>=0; i--)
			if (ProxyUtils.isProxy(chain[i]))
			{
				firstProxy = i;
				this.chain = chain;
				break;
			}
		if (i == -1)
			throw new CertificateException("There is no proxy certificate in the chain");
	}

	/**
	 * 
	 * @return array with serial numbers of the certificates in the chain
	 */
	public BigInteger[] getSerialNumbers() 
	{
		BigInteger[] ret = new BigInteger[chain.length];
		for (int i=0; i<chain.length; i++)
			ret[i] = chain[i].getSerialNumber();
		return ret;
	}
	
	/**
	 * The type of the proxy chain chain is returned. If chain contains
	 * different types then MIXED type is returned.
	 * @return the type of the chain
	 * @throws CertificateException certificate exception
	 */
	public ProxyChainType getProxyType() throws CertificateException 
	{
		if (type != null)
			return type;
		
		for (int i=0; i<=firstProxy; i++)
		{
			ExtendedProxyType ptype = ProxyHelper.getProxyType(chain[i]);
			switch (ptype)
			{
			case NOT_A_PROXY:
				break;
			case DRAFT_RFC:
				if (type == null)
					type = ProxyChainType.DRAFT_RFC;
				else if (type != ProxyChainType.DRAFT_RFC)
					type = ProxyChainType.MIXED;
				break;
			case RFC3820:
				if (type == null)
					type = ProxyChainType.RFC3820;
				else if (type != ProxyChainType.RFC3820)
					type = ProxyChainType.MIXED;
				break;
			case LEGACY:
				if (type == null)
					type = ProxyChainType.LEGACY;
				else if (type != ProxyChainType.LEGACY)
					type = ProxyChainType.MIXED;
			}
		}
		return type;
	}

	/**
	 * @return the index of the first proxy in the chain (issued by the EEC).
	 */
	public int getFirstProxyPosition() 
	{
		return firstProxy;
	}

	/**
	 * Used to check whether the proxy chain is limited or not.
	 * The method returns 'true' if and only if there is at least one limited 
	 * proxy in the chain.
	 * @return true if the chain is limited, i.e. owner of the certificate
	 * may not submit jobs
	 * @throws CertificateException certificate exception
	 * @throws IOException IO exception
	 */
	public boolean isLimited() throws CertificateException, IOException 
	{
		if (limited != null)
			return limited;
		for (int i=0; i<=firstProxy; i++)
			if (ProxyHelper.isLimited(chain[i]))
			{
				limited = true;
				return true;
			}
		limited = false;
		return false;
	}

	/**
	 * Gets the array of RFC proxy extension policy OID and octets of the
	 * policy. See RFC3820. Policy octets can be null in case the OID in itself
	 * defines the behavior, like with "inherit all" policy or
	 * "independent" policy. The array contains entries from all certificates 
	 * in chain.
	 * @return array with policy information
 	 * @throws IOException Thrown in case the parsing of the information failed.
	 */
	public ProxyPolicy[] getPolicy() throws IOException 
	{
		if (policy != null)
			return policy;
		
		List<ProxyPolicy> policies = new ArrayList<ProxyPolicy>();
		for (int i=firstProxy; i>=0; i--)
		{
			ExtendedProxyType type = ProxyHelper.getProxyType(chain[i]);
			if (type == ExtendedProxyType.DRAFT_RFC || 
					type == ExtendedProxyType.RFC3820)
			{
				ProxyCertInfoExtension ext = ProxyCertInfoExtension.getInstance(chain[i]);
				if (ext != null)
					policies.add(ext.getPolicy());
			}
		}
		policy = policies.toArray(new ProxyPolicy[policies.size()]);
		return policy;
	}

	/**
	 * Returns an array of URLs of the proxy tracing issuers in 
	 * the chain. Non-traced proxies will have null in the array.
	 * 
	 * @return The proxy tracing issuer URLs in String format, or null in the 
	 * array if an extension was not found or it was empty.
	 * @throws IOException Thrown in case the parsing of the information failed.
	 */
	public String[] getProxyTracingIssuers() throws IOException 
	{
		String ret[] = new String[chain.length];
		for (int i=0; i<chain.length; i++)
		{
			ProxyTracingExtension extension = ProxyTracingExtension.getInstance(chain[i], true);
			ret[i] = extension == null ? null : extension.getURL();
		}
		return ret;	
	}

	/**
	 * Returns an array of URLs of the proxy tracing subjects in the chain. 
	 * Non-traced proxies will have null in the array.
	 * @return The proxy tracing subject URLs in String format, or null in the 
	 * array if an extension was not found or it was empty.
	 * @throws IOException Thrown in case the parsing of the information failed.
	 */
	public String[] getProxyTracingSubjects() throws IOException {
		String ret[] = new String[chain.length];
		for (int i=0; i<chain.length; i++)
		{
			ProxyTracingExtension extension = ProxyTracingExtension.getInstance(chain[i], false);
			ret[i] = extension == null ? null : extension.getURL();
		}
		return ret;	
	}

	/**
	 * Returns the SAML extensions from the certificate chain.
	 * @return The SAML assertions in String format. A null in the array 
	 * means that no SAML extensions were found at the given position.
	 * @throws IOException Thrown in case the parsing of the information failed.
	 */
	public String[] getSAMLExtensions() throws IOException 
	{
		String ret[] = new String[chain.length];
		for (int i=0; i<chain.length; i++)
		{
			ProxySAMLExtension extension = ProxySAMLExtension.getInstance(chain[i]);
			if (extension != null)
				ret[i] = extension.getSAML();

		}
		return ret;	
	}

	/**
	 * Returns the Attribute Certificate extensions from the certificate chain.
	 * @return The Attribute Certificates array. The first index corresponds to the 
	 * first certificate in the chain. A null in the array 
	 * means that no AC extension was found at the given position.
	 * @throws IOException Thrown in case the parsing of the information failed.
	 */
	public AttributeCertificate[][] getAttributeCertificateExtensions() throws IOException 
	{
		AttributeCertificate ret[][] = new AttributeCertificate[chain.length][];
		for (int i=0; i<chain.length; i++)
		{
			ProxyACExtension extension = ProxyACExtension.getInstance(chain[i]);
			if (extension != null)
				ret[i] = extension.getAttributeCertificates();
		}
		return ret;	
	}

	/**
	 * Returns the remaining path length of this chain. Will 
	 * search for both the RFC 3820 and the draft proxy path limit extensions. 
	 * Legacy proxies are treated as unlimited.
	 * <p> 
	 * Notice: negative value means that the chain is invalid as 
	 * it has passed the limit of delegations. Integer.MAX_INT is returned
	 * if there is no path length limit set on the chain.
	 * 
	 * @return remaining proxy path limit
	 * @throws IOException Thrown in case the parsing of the information failed.
	 */
	public int getRemainingPathLimit() throws IOException 
	{
		int remainingLen = Integer.MAX_VALUE;
		for (int i=firstProxy; i>=0; i--)
		{
			int lenRestriction = ProxyHelper.getProxyPathLimit(chain[i]);
			if (lenRestriction < remainingLen)
				remainingLen = lenRestriction;
			else
				remainingLen--;
		}
		return remainingLen;
		
	}

	/**
	 * Gets the proxy source restriction data from the chain. 
	 * The allowed namespaces in different certificates in the
	 * chain will be intersected and the excluded namespaces will be summed. 
	 * The returned array has as the first item the array of allowed 
	 * namespaces and as the second item the array of excluded namespaces. 
	 * If extensions exist, but in the end no allowed or excluded namespaces are left, 
	 * the array is empty.
	 * 
	 * @return array with proxy source restrictions. Null is returned when there is no restriction defined
	 * for any of the proxies in the chain.
	 * @throws IOException Thrown in case the parsing of the information failed.
	 */
	public byte[][][] getProxySourceRestrictions() throws IOException 
	{
		return getProxyRestrictions(true);
	}

	/**
	 * Gets the proxy target restriction data from the chain. The allowed 
	 * namespaces in different certificates in the
	 * chain will be intersected and the union of the excluded namespaces will be computed. 
	 * The returned array has as the first item the array of allowed namespaces 
	 * and as the second item the array of excluded namespaces. If extensions exist, but in the end 
	 * no allowed or excluded namespaces are left, the array is empty. 
	 * 
	 * @return array with proxy target restrictions. Null is returned when there is no restriction defined
	 * for any of the proxies in the chain.
	 * @throws IOException Thrown in case the parsing of the information failed.
	 */
	public byte[][][] getProxyTargetRestrictions() throws IOException 
	{
		return getProxyRestrictions(false);
	}
	
	/**
	 * Checks if the given IP address is allowed as this proxy chain source.
	 * 
	 * @param ipAddress host IPv4 address in 4 elements array 
	 * @return true if and only if the ipAddress is OK w.r.t. this proxy 
	 * chain's source restrictions.
	 * @throws IOException Thrown in case the parsing of the information failed.
	 */
	public boolean isHostAllowedAsSource(byte[] ipAddress) throws IOException 
	{
		return isHostAllowed(ipAddress, getProxySourceRestrictions());
	}

	/**
	 * Checks if the given IP address is allowed as this proxy chain target.
	 * 
	 * @param ipAddress host IPv4 address in 4 elements array 
	 * @return true if and only if the ipAddress is OK w.r.t. this proxy 
	 * chain's source restrictions.
	 * @throws IOException Thrown in case the parsing of the information failed.
	 */
	public boolean isHostAllowedAsTarget(byte[] ipAddress) throws IOException 
	{
		return isHostAllowed(ipAddress, getProxyTargetRestrictions());
	}
	
	/**
	 * Calculates the union of the newSpaces and the given vectors of IPv4
	 * and IPv6 namespaces.
	 * 
	 * @param newSpaces
	 *                The namespaces to add.
	 * @param ipV4Spaces
	 *                The old IPv4 spaces.
	 * @param ipV6Spaces
	 *                The old IPv6 spaces.
	 * @return the two resulting vectors, IPv4 vector first and the IPv6
	 *         vector second.
	 */
	private List<List<byte[]>> union(byte[][] newSpaces, List<byte[]> ipV4Spaces,
			List<byte[]> ipV6Spaces)
	{
		List<List<byte[]>> ret = new ArrayList<List<byte[]>>();
		if (newSpaces == null)
		{
			ret.add(ipV4Spaces);
			ret.add(ipV6Spaces);
			return ret;
		}
		List<byte[]> newIPv4 = new ArrayList<byte[]>();
		List<byte[]> newIPv6 = new ArrayList<byte[]>();

		if (ipV4Spaces != null)
			newIPv4.addAll(ipV4Spaces);
		if (ipV6Spaces != null)
			newIPv6.addAll(ipV6Spaces);

		for (int i = 0; i < newSpaces.length; i++)
		{
			if (newSpaces[i].length == 8)
			{
				newIPv4.add(newSpaces[i]);
			} else
			{
				if (newSpaces[i].length == 32)
				{
					newIPv6.add(newSpaces[i]);
				} else
				{
					throw new IllegalArgumentException(
							"IP space definition has to be either 8 bytes or 32 bytes, length was: "
									+ newSpaces.length);
				}
			}
		}
		ret.add(newIPv4);
		ret.add(newIPv6);
		return ret;
	}

	/**
	 * Calculates the intersection of the newSpaces and the given lists of
	 * IPv4 and IPv6 namespaces.
	 * 
	 * @param newSpaces
	 *                The namespaces to intersect with.
	 * @param ipV4Spaces
	 *                The old IPv4 spaces.
	 * @param ipV6Spaces
	 *                The old IPv6 spaces.
	 * @return the two resulting lists, IPv4 list first and the IPv6
	 *         list second.
	 */
	private List<List<byte[]>> intersection(byte[][] newSpaces, List<byte[]> ipV4Spaces,
			List<byte[]> ipV6Spaces)
	{
		List<List<byte[]>> ret = new ArrayList<List<byte[]>>();
		if (newSpaces == null)
		{
			ret.add(ipV4Spaces);
			ret.add(ipV6Spaces);
			return ret;
		}
		List<byte[]> newIPv4 = new ArrayList<byte[]>();
		List<byte[]> newIPv6 = new ArrayList<byte[]>();

		for (int i = 0; i < newSpaces.length; i++)
		{
			List<byte[]> newIPs;
			int len;
			if (newSpaces[i].length == 8)
			{
				newIPs = newIPv4;
				len = 8;
			} else
			{
				if (newSpaces[i].length == 32)
				{
					newIPs = newIPv6;
					len = 32;
				} else
				{
					throw new IllegalArgumentException(
							"Invalid namespace definition, length should be 8 or 32 bytes. It was: "
							+ newSpaces[i].length + " bytes.");
				}
			}
			if (ipV4Spaces != null && ipV6Spaces != null)
			{
				byte[] ip = Arrays.copyOfRange(newSpaces[i], 0, len / 2);

				Iterator<byte[]> iter = newIPs.iterator();
				while (iter.hasNext())
				{
					byte[] oldSpace = iter.next();
					if (IPAddressHelper.isWithinAddressSpace(ip, oldSpace))
					{
						boolean newTighter = true;
						for (int n = 0; n < len / 2; n++)
						{
							if ((oldSpace[n + len / 2] & 0xFF) < (newSpaces[i][n
									+ len / 2] & 0xFF))
							{
								newTighter = false;
								break;
							}
						}
						if (newTighter)
						{
							newIPs.add(newSpaces[i]);
						} else
						{
							newIPs.add(oldSpace);
						}
					}
				}
			} else
			{
				newIPs.add(newSpaces[i]);
			}
		}

		ret.add(newIPv4);
		ret.add(newIPv6);
		return ret;
	}

	/**
	 * Goes through the whole proxy chain and collects and combines either
	 * the source restrictions or target restrictions.
	 * 
	 * @param source true if source extensions are to be collected. False
	 *                if target extensions are to be collected.
	 * @return The collected and combined restriction data.
	 * @throws IOException Thrown in case a certificate parsing fails.
	 */
	private byte[][][] getProxyRestrictions(boolean source) throws IOException
	{
		List<byte[]> allowedIPv4Spaces = null;
		List<byte[]> allowedIPv6Spaces = null;
		List<byte[]> excludedIPv4Spaces = null;
		List<byte[]> excludedIPv6Spaces = null;

		boolean found = false;
		for (int i = chain.length - 1; i >= 0; i--)
		{
			ProxyAddressRestrictionData restrictions = ProxyAddressRestrictionData.getInstance(
					chain[i], source);
			if (restrictions != null)
			{
				found = true;
				byte[][][] spaces = restrictions.getIPSpaces();
				List<List<byte[]>> newSpaces = intersection(spaces[0],
						allowedIPv4Spaces, allowedIPv6Spaces);
				allowedIPv4Spaces = newSpaces.get(0);
				allowedIPv6Spaces = newSpaces.get(1);

				newSpaces = union(spaces[1], excludedIPv4Spaces, excludedIPv6Spaces);
				excludedIPv4Spaces = newSpaces.get(0);
				excludedIPv6Spaces = newSpaces.get(1);
			}
		}
		if (!found)
			return null;

		byte[][][] newSpaces = new byte[2][][];
		

		if (allowedIPv4Spaces != null && allowedIPv6Spaces != null)
		{
			newSpaces[0] = concatArrays(
					allowedIPv4Spaces.toArray(new byte[0][0]),
					allowedIPv6Spaces.toArray(new byte[0][0]));
		} else
			newSpaces[0] = new byte[0][];
		if (excludedIPv4Spaces != null && excludedIPv6Spaces != null)
		{
			newSpaces[1] = concatArrays(
					excludedIPv4Spaces.toArray(new byte[0][0]),
					excludedIPv6Spaces.toArray(new byte[0][0]));
		} else
			newSpaces[1] = new byte[0][];

		return newSpaces;
	}

	private boolean isHostAllowed(byte[] ipAddress, byte[][][] restrictions) throws IOException 
	{
		if (restrictions == null)
			return true;
		for (int i=0; i<restrictions[1].length; i++)
			if (IPAddressHelper.isWithinAddressSpace(ipAddress, restrictions[1][i]))
				return false;
		for (int i=0; i<restrictions[0].length; i++)
			if (IPAddressHelper.isWithinAddressSpace(ipAddress, restrictions[0][i]))
				return true;
		return false;
	}

	/**
	 * Concatenates two arrays of arrays bytes.
	 * 
	 * @param first
	 *                The array of arrays to begin with.
	 * @param second
	 *                The array of arrays to end with.
	 * @return the array of arrays that contains the arrays from both
	 *         argument arrays.
	 */
	public static byte[][] concatArrays(byte[][] first, byte[][] second)
	{
		int firstLen = first.length;
		int secondLen = second.length;
		byte[][] newByteArrays = new byte[firstLen + secondLen][];
		for (int i = 0; i < firstLen; i++)
			newByteArrays[i] = first[i];
		for (int i = 0; i < secondLen; i++)
			newByteArrays[i + firstLen] = second[i];
		return newByteArrays;
	}

}
