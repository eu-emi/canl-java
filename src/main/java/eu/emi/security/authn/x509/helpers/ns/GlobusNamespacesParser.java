/*
 * Copyright (c) 2011 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.ns;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import eu.emi.security.authn.x509.helpers.trust.OpensslTrustAnchorStore;
import eu.emi.security.authn.x509.impl.OpensslNameUtils;

/**
 * Parses a single .signing_policy file and returns {@link NamespacePolicy} object.
 * Only the simplified parsing of the EACL format is implemented, in a similar way is in case 
 * of a native Globus implementation. However there are differences. First of all the format
 * of this file is defined in a very imprecise way.
 * <p>
 * The parsing is done in the following way:
 * <ul>
 * <li> as a whitespace the space and tab characters are used; a separator may 
 * contain an arbitrary number of those, below only one space was used for clarity.
 * <li> all empty lines, whitespace only lines and lines beginning with '#' are ignored
 * <li> the first line like this is searched:
 * access_id_CA X509 'ANY_STRING'
 * other are ignored. Line with the access_id_CA prefix and other ending causes an error. 
 * <li> after this line it is expected that the next significant line is :
 * pos_rights globus CA:sign
 * <li> next the line in the format:
 * cond_subjects globus '"ANY_STRING" ["ANY_STRING"]'
 * is expected. The trailing string need not to be enclosed in '' and in "", but if it is
 * then the order of quotation must be preserved.
 * <li> go to step 3.
 * </ul>
 * @author K. Benedyczak
 */
public class GlobusNamespacesParser implements NamespacesParser
{
	public static String ACCESS_ID_CA = "access_id_CA";
	public static String DEF_AUTH_X509 = "X509";
	public static String DEF_AUTH_GLOBUS = "globus";
	public static String POS_RIGHTS = "pos_rights";
	public static String CONDITION_SUBJECT = "cond_subjects";    
	public static String VALUE_CA_SIGN = "CA:sign";
	public static final String NS_REGEXP = "^([0-9a-fA-F]{8})\\.signing_policy$";


	private String filePath;
	private String hash;
	private String issuer;
	private List<NamespacePolicy> ret;
	
	public GlobusNamespacesParser(String filePath)
	{
		this.filePath = filePath;
	}

	public List<NamespacePolicy> parse() throws IOException
	{
		hash = OpensslTrustAnchorStore.getFileHash(filePath, NS_REGEXP);
		if (hash == null)
			throw new IOException("Policy file name " + filePath + 
					" is incorrect: it must be formed from 8 charater subject hash and " +
					"'.signing_policy' extension.");
		BufferedReader reader = new BufferedReader(new FileReader(filePath));
		try
		{
			String line;
			ret = new ArrayList<NamespacePolicy>();
			while ((line = reader.readLine()) != null)
			{
				line = line.trim();
				if (!isValid(line))
					continue;
				if (!line.startsWith(ACCESS_ID_CA))
					continue;
				handleCABlock(line, reader);
			}
			return ret;
		} finally 
		{
			reader.close();
		}
	}
	
	private void handleCABlock(String line, BufferedReader reader) throws IOException
	{
		char[] caChars = line.toCharArray();
		int i = ACCESS_ID_CA.length();
		i += eatSpaces(caChars, i, true);
		i += ParserUtils.checkToken(DEF_AUTH_X509, caChars, i, true);
		i += eatSpaces(caChars, i, true);
		StringBuilder issuerBuf = new StringBuilder();
		i += getQuoted(caChars, i, '\'', issuerBuf);
		issuer = issuerBuf.toString();
		ParserUtils.checkEndOfLine(caChars, i);
		
		while ((line = reader.readLine()) != null)
		{
			line = line.trim();
			if (!isValid(line))
				continue;
			handleAuthEntry(line, reader);
			break;
		}
	}
	
	private void handleAuthEntry(String line, BufferedReader reader) throws IOException
	{
		char[] chars = line.toCharArray();
		int j=0;
		j += ParserUtils.checkToken(POS_RIGHTS, chars, j, true);
		j += eatSpaces(chars, j, true);
		j += ParserUtils.checkToken(DEF_AUTH_GLOBUS, chars, j, true);
		j += eatSpaces(chars, j, true);
		j += ParserUtils.checkToken(VALUE_CA_SIGN, chars, j, true);
		ParserUtils.checkEndOfLine(chars, j);
		
		while ((line = reader.readLine()) != null)
		{
			line = line.trim();
			if (!isValid(line))
				continue;
			handlePermitEntry(line, reader);
			break;
		}
	}

	private void handlePermitEntry(String line, BufferedReader reader) throws IOException
	{
		char[] chars = line.toCharArray();
		int j=0;
		j += ParserUtils.checkToken(CONDITION_SUBJECT, chars, j, true);
		j += eatSpaces(chars, j, true);
		j += ParserUtils.checkToken(DEF_AUTH_GLOBUS, chars, j, true);
		j += eatSpaces(chars, j, true);
		StringBuilder subject = new StringBuilder();
		j += getQuoted(chars, j, '\'', subject);
		ParserUtils.checkEndOfLine(chars, j);
		
		addPermitted(subject.toString());
	}
	
	private void addPermitted(String permitted) throws IOException
	{
		char []subjectWildcards = permitted.toCharArray();
		int i=0;
		do 
		{
			int spaces = eatSpaces(subjectWildcards, i, false); 
			i += spaces;
			if (i==0) //first element->spaces not needed.
				spaces++; 
			StringBuilder permittedBuf = new StringBuilder(); 
			i += getQuoted(subjectWildcards, i, '"', permittedBuf);
			permitted = permittedBuf.toString().trim();
			if (permitted.length() == 0)
				break;
			if (spaces == 0)
				throw new IOException("Syntax problem, space character(s) missing in: " + 
						new String(subjectWildcards, 0, subjectWildcards.length));
//			List<String> permittedList = normalize(permitted);
//			for (String p: permittedList)
//			{
//				NamespacePolicy policy = new NamespacePolicy(
//					ParserUtils.normalize(issuer), 
//					p, true, filePath);
//				ret.add(policy);
//			}
			String permittedNormal = normalize(permitted);
			NamespacePolicy policy = new OpensslNamespacePolicyImpl(
					OpensslNameUtils.normalize(issuer), permittedNormal, hash, true, filePath);
			ret.add(policy);
			
		} while (true);
	}
	
	private int getQuoted(char[] string, int offset, char quoteChar, StringBuilder ret) throws IOException
	{
		int count = string.length-offset;
		int all = count;
		if (count <= 0)
			return 0;
		if (string[offset] == quoteChar)
		{
			if (count < 2)
				throw new IOException("Syntax problem, quoted string is not properly ended: '" 
						+ new String(string, offset, string.length-offset));
			offset++;
			int finish = offset + eatUntil(string, offset, quoteChar);
			count = finish-offset;
			all = count+2;
		}
		ret.append(string, offset, count);
		return all;
	}
	
	private boolean isValid(String line)
	{
		if (line.equals("") || line.startsWith("#"))
			return false;
		return true;
	}
	
	private int eatSpaces(char[] string, int offset, boolean atLeastOne) throws IOException
	{
		int i=0;
		while (i+offset < string.length && (string[i+offset] == ' ' 
				|| string[i+offset] == '\t'))
			i++;
		if (atLeastOne && i==0)
			throw new IOException("Syntax problem, expected space character(s) here: " + 
					new String(string, offset, string.length-offset));
		return i;
	}
	
	private int eatUntil(char[] string, int offset, char delimiter) throws IOException
	{
		int i=0;
		while (i+offset < string.length && (string[i+offset] != delimiter))
			i++;
		if (i+offset == string.length)
			throw new IOException("Syntax problem, quoted string is not properly ended: '" 
					+ new String(string, offset, string.length-offset));
		return i;
	}
	

	
	
	
	public static String normalize(String dn)
	{
		dn = OpensslNameUtils.normalize(dn);
		return makeRegexpClassicWildcard(dn);
	}
	
	/**
	 * Converts wildcard string to Java regexp, ensuring that 
	 * literal sequences are correctly escaped. 
	 * @param pattern input wildcard
	 * @return Java regular expression
	 */
	public static String makeRegexpClassicWildcard(String pattern)
	{
		String wPattern = pattern;
		String REP_STAR = ".*";
		String REP_QUESTION = ".";
		StringBuilder patternB = new StringBuilder();
		int pos = 0;
		while (wPattern.startsWith("*") || wPattern.startsWith("?"))
		{
			if (wPattern.startsWith("*"))
				patternB.append(REP_STAR);
			else
				patternB.append(REP_QUESTION);
			wPattern = wPattern.substring(1);
		}
		int endingSize = 0;
		while (wPattern.endsWith("*") || wPattern.endsWith("?"))
		{
			wPattern = wPattern.substring(0, wPattern.length()-1);
			endingSize++;
		}
		
		String[] rPNames = wPattern.split("\\*|\\?");
		for (int i=0; i<rPNames.length; i++)
		{
			if (rPNames[i].length() > 0)
			{
				patternB.append(Pattern.quote(rPNames[i]));
				pos += rPNames[i].length();
			}
			
			if (i+1<rPNames.length)
			{
				char orig = wPattern.charAt(pos);
				if (orig == '?')
					patternB.append(REP_QUESTION);
				else if (orig == '*')
					patternB.append(REP_STAR);
				else
					throw new RuntimeException("Bug: should get ? or * on the split position");
				pos++;
			}
		}
		char []patternC = pattern.toCharArray();
		for (int i=patternC.length-endingSize; i<patternC.length; i++)
		{
			if (patternC[i] == '*')
				patternB.append(REP_STAR);
			else 
				patternB.append(REP_QUESTION);
		}
		return patternB.toString();
	}

}
