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

/**
 * Helpers for IP addresses comparison.
 * Mostly the code from Tigran's ipmatcher library (GNU license). 
 * 
 * @author Tigran Mkrtchyan
 * @author K. Benedyczak
 */
public class IPAddressHelper
{
	private static final int IPv4_FULL_MASK = 32;
	private static final int IPv6_FULL_MASK = 128;
	private static final int IPv6_HALF_MASK = 64;
	
	/**
	 * Tests whether the ipAddress is within the address space defined by
	 * the ipAddressWithNetmask.
	 * 
	 * @param ipBytes
	 *                The IP address bytes to compare against the address
	 *                space.
	 * @param ipAddressWithNetmask
	 *                The 8 (IPv4) or 32 (IPv6) byte array containing in the
	 *                first half the base IP address bytes and in the second
	 *                half the netmask bytes.
	 * @return true if ip matches subnet.
	 */
	public static boolean isWithinAddressSpace(byte[] ipBytes, byte[] ipAddressWithNetmask) {

		if (!(ipAddressWithNetmask.length == 8 && ipBytes.length == 4)
				&& !(ipAddressWithNetmask.length == 32 && ipBytes.length == 16))
		{
			throw new IllegalArgumentException(
					"IP address and IP address-netmask length mismatch, should be either (4 and 8) or (16 and 32), actual lengths were: "
							+ ipBytes.length
							+ " and "
							+ ipAddressWithNetmask.length + ".");
		}

		if (ipBytes.length == 4) {
			 
			int mask = getCidrNetmask(4, ipAddressWithNetmask, 4);
			/*
			 * IPv4 can be represented as a 32 bit ints.
			 */
			int ipAsInt = getInt(ipBytes, 0);
			int netAsInt = getInt(ipAddressWithNetmask, 0);

			return (ipAsInt ^ netAsInt) >> (IPv4_FULL_MASK - mask) == 0;
		}

		/**
		 * IPv6 can be represented as two 64 bit longs.
		 * 
		 * We evaluate second long only if bitmask bigger than 64. The
		 * second longs are created only if needed as it turned to be
		 * the slowest part.
		 */
		long ipAsLong0 = getLong(ipBytes, 0);
		long netAsLong0 = getLong(ipAddressWithNetmask, 0);
		int mask = getCidrNetmask(16, ipAddressWithNetmask, 16);

		if (mask > 64) {
			long ipAsLong1 = getLong(ipBytes, 8);
			long netAsLong1 = getLong(ipAddressWithNetmask, 8);

			return (ipAsLong0 == netAsLong0)
					& (ipAsLong1 ^ netAsLong1) >> (IPv6_FULL_MASK - mask) == 0;
		}
		return (ipAsLong0 ^ netAsLong0) >> (IPv6_HALF_MASK - mask) == 0;
	}

	/**
	 * Returns the big-endian {@code long} value whose byte representation
	 * is the 8 bytes of <code>bytes</code> staring <code>offset</code>.
	 * 
	 * @param bytes
	 * @param offset
	 * @return long value
	 */
	private static long getLong(byte[] bytes, int offset) {
		return (bytes[offset] & 0xFFL) << 56 | (bytes[offset + 1] & 0xFFL) << 48
				| (bytes[offset + 2] & 0xFFL) << 40
				| (bytes[offset + 3] & 0xFFL) << 32
				| (bytes[offset + 4] & 0xFFL) << 24
				| (bytes[offset + 5] & 0xFFL) << 16
				| (bytes[offset + 6] & 0xFFL) << 8 | (bytes[offset + 7] & 0xFFL);
	}

	/**
	 * Returns the big-endian {@code int} value whose byte representation is
	 * the 4 bytes of <code>bytes</code> staring <code>offset</code>.
	 * 
	 * @param bytes
	 * @param offset
	 * @return int value
	 */
	private static int getInt(byte[] bytes, int offset) {
		return (bytes[offset + 0] & 0xFF) << 24 | (bytes[offset + 1] & 0xFF) << 16
				| (bytes[offset + 2] & 0xFF) << 8 | (bytes[offset + 3] & 0xFF);
	}
	
	private static int getCidrNetmask(int size, byte[] netmask, int offset)
	{
		int ret = 0;
		for (int i=0; i<size; i++)
		{
			if (netmask[i+offset] != -1) //-1 == 255 unsigned
			{
				int maskByteReversed = (~(netmask[i+offset]))&0xff;
				int bitPfx = Integer.numberOfLeadingZeros(maskByteReversed)-24;
				return ret+bitPfx;
			} else
				ret += 8;
		}
		return ret;
	}
}
