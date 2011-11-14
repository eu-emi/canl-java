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

import java.util.Arrays;

/**
 * Helpers for IP addresses comparison.
 * 
 * @author Joni Hahkala
 * @author K. Benedyczak
 */
public class IPAddressHelper
{
	/**
	 * Tests whether the ipAddress is within the address space defined by
	 * the ipAddressWithNetmask.
	 * 
	 * @param ipAddress
	 *                The IP address bytes to compare against the address
	 *                space.
	 * @param ipAddressWithNetmask
	 *                The 8 (IPv4) or 32 (IPv6) byte array containing in the
	 *                first half the base IP address bytes and in the second
	 *                half the netmask bytes.
	 * @return true if
	 */
	public static boolean isWithinAddressSpace(byte[] ipAddress, byte[] ipAddressWithNetmask)
	{
		if (!(ipAddressWithNetmask.length == 8 && ipAddress.length == 4)
				&& !(ipAddressWithNetmask.length == 32 && ipAddress.length == 16))
		{
			throw new IllegalArgumentException(
					"IP address and IP address-netmask length mismatch, should be either (4 and 8) or (16 and 32) lengths were: "
							+ ipAddress.length
							+ " and "
							+ ipAddressWithNetmask.length + ".");
		}

		byte[] comparatorIP = Arrays.copyOfRange(ipAddressWithNetmask, 0,
				ipAddressWithNetmask.length / 2);
		byte[] netmask = Arrays.copyOfRange(ipAddressWithNetmask, ipAddressWithNetmask.length / 2,
				ipAddressWithNetmask.length);

		byte[] resultComparator = andBytes(comparatorIP, netmask);
		byte[] resultIP = andBytes(ipAddress, netmask);
		return Arrays.equals(resultComparator, resultIP);

	}

	/**
	 * This method does bitwise and between the two byte arrays. The arrays
	 * have to have the same size.
	 * 
	 * @param ip
	 *                The first array to use for the and operation.
	 * @param netmask
	 *                The second array to use for the and operation.
	 * @return The resulting byte array containing the bytes after the
	 *         bitwise and operation.
	 */
	public static byte[] andBytes(byte[] ip, byte[] netmask)
	{
		if (ip.length != netmask.length)
		{
			throw new IllegalArgumentException(
					"Illegal array sizes given for and operation, sizes must match, sizes were: "
							+ ip.length + " and " + netmask.length
							+ ".");
		}
		byte[] result = new byte[ip.length];
		for (int i = 0; i < ip.length; i++)
		{
			Integer integer = Integer.valueOf((ip[i] & 0xFF) & (netmask[i] & 0xFF));
			result[i] = integer.byteValue();
		}
		return result;
	}
}
