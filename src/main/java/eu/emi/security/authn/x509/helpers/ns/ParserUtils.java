/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.ns;

import java.io.IOException;

/**
 * Common helpers for namespace file parsers.
 * @author K. Benedyczak
 */
public class ParserUtils
{
	public static int checkToken(String token, char[] chars, int offset, 
			boolean caseSensitive) throws IOException
	{
		int ret = checkTokenSoft(token, chars, offset, caseSensitive);
		if (ret < 0)
			throw new IOException("Syntax problem, expected token '" + token + "' but got: '" + 
					new String(chars, offset, chars.length-offset));
		return ret;
	}
	
	public static int checkTokenSoft(String token, char[] chars, int offset, 
			boolean caseSensitive)
	{
		char []tokenChars = token.toCharArray();
		if (chars.length < offset + tokenChars.length)
			return -1;
		int i=0;
		for (; i<tokenChars.length; i++)
		{
			char a = caseSensitive ? tokenChars[i] : Character.toLowerCase(tokenChars[i]);
			char b = caseSensitive ? chars[i+offset] : Character.toLowerCase(chars[i+offset]);
			if (a != b)
				return -1;
		}
		return i;
	}
	
	public static void checkEndOfLine(char []chars, int j) throws IOException
	{
		if (j < chars.length)
			throw new IOException("Syntax problem, garbage at the end of line: " + 
					new String(chars, j, chars.length-j));
	}
}
