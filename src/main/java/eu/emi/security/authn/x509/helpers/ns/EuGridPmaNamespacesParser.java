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

import eu.emi.security.authn.x509.helpers.CertificateHelpers;
import eu.emi.security.authn.x509.helpers.trust.OpensslTrustAnchorStore;
import eu.emi.security.authn.x509.impl.X500NameUtils;

/**
 * Parses a single EUGridPMA namespaces file and returns {@link NamespacePolicy} object.
 * The syntax is defined in the document (available from the EUGridPMA website): 
 * eugridpma-namespaces-format-spec-20060113-0-1-4.doc, Mon, 16 January 2006.
 * This class is not thread safe.
 * @author K. Benedyczak
 */
public class EuGridPmaNamespacesParser implements NamespacesParser
{
	private static final String VERSION_KEY = "#NAMESPACES-VERSION: ";
	public static final String NS_REGEXP = "^([0-9a-fA-F]{8})\\.namespaces$";
	private static final String SUPPORTED_VERSION = "1.0";
	private String filePath;
	
	private String hash;
	private String issuer;
	private String subject;
	private boolean permit;
	
	public EuGridPmaNamespacesParser(String filePath)
	{
		this.filePath = filePath;
	}
	
	
	public List<NamespacePolicy> parse() throws IOException 
	{
		hash = OpensslTrustAnchorStore.getFileHash(filePath, NS_REGEXP);
		if (hash == null)
			throw new IOException("Policy file name " + filePath + 
					" is incorrect: it must be formed from 8 charater subject hash and " +
					"'.namespaces' extension.");
		BufferedReader reader = new BufferedReader(new FileReader(filePath));
		String line;
		StringBuilder fullLine = new StringBuilder();
		int entryNumber = 1;
		List<NamespacePolicy> ret = new ArrayList<NamespacePolicy>();
		while ((line = reader.readLine()) != null)
		{
			line = stripComments(line);
			if (line.endsWith("\\") && !line.endsWith("\\\\")) 
			{
				fullLine.append(line.substring(0, line.length() - 1));
				continue;
			}
			fullLine.append(line);
			String entry = fullLine.toString().trim();
			if (entry.length() == 0)
				continue;
			handleEntry(entry);
			
			if (issuer.contains("=")) //otherwise assume it is hash
				issuer = ParserUtils.normalize(issuer);
			List<String> subjects = normalize(subject);
			for (String subject: subjects)
			{
				ret.add(new NamespacePolicy(issuer, 
					subject, 
					permit, filePath + ":" + entryNumber));
			}
			fullLine = new StringBuilder();
			entryNumber++;
		}
		return ret;
	}
	
	protected String stripComments(String from) throws IOException
	{
		if (from.startsWith(VERSION_KEY))
		{
			String version = from.substring(VERSION_KEY.length());
			if (!version.equals(SUPPORTED_VERSION))
				throw new IOException("Namespaces policy version " + 
						version + " is unsupported");
			return "";
		}
		char[] chars = from.toCharArray();
		for (int i=0; i<chars.length; i++)
		{
			boolean escaped = false;
			if (chars[i] == '\\' && i<chars.length-1)
			{
				i++;
				escaped = true;
			}
			if (chars[i] == '#' && !escaped)
				return from.substring(0, i);
		}
		return from;
	}
	
	protected void handleEntry(String line) throws IOException
	{
		char[] chars = line.toCharArray();
		int i=0;
		i += ParserUtils.checkToken("to", chars, 0, false);
		i += eatSpaces(chars, i, true);
		i += ParserUtils.checkToken("issuer", chars, i, false);
		i += eatSpaces(chars, i, true);
		
		if (chars[i] == '"')
		{
			StringBuilder sb = new StringBuilder();
			i += consumeQuoted(chars, i, sb);
			issuer = sb.toString();
		} else
		{
			int r = ParserUtils.checkTokenSoft("self", chars, i, false);
			if (r < 0)
				throw new IOException("Syntax problem, expected either a quoted issuer DN or the SELF token. Got: " + 
						new String(chars, i, chars.length-i));
			i += r;
			issuer = hash;
		}
		
		i += eatSpaces(chars, i, true);
		int r = ParserUtils.checkTokenSoft("permit", chars, i, false);
		permit = true;
		if (r < 0)
		{
			r = ParserUtils.checkTokenSoft("deny", chars, i, false);
			permit = false;
		}
		if (r < 0)
			throw new IOException("Syntax problem, expected PERMIT or DENY token. Got: " + 
					new String(chars, i, chars.length-i));
		i += r;
		
		i += eatSpaces(chars, i, true);
		i += ParserUtils.checkToken("subject", chars, i, false);
		i += eatSpaces(chars, i, true);
		
		StringBuilder sb = new StringBuilder();
		i += consumeQuoted(chars, i, sb);
		ParserUtils.checkEndOfLine(chars, i);
		
		subject = sb.toString();
	}


	
	protected int consumeQuoted(char[] chars, int offset, StringBuilder ret) throws IOException
	{
		if (chars[offset] != '"' || chars.length < offset+2)
			throw new IOException("Syntax problem, expected a quoted string but got: " + 
					new String(chars, offset, chars.length-offset));
		for (int i=1+offset; i<chars.length; i++)
		{
			boolean escaped = false;
			if (chars[i] == '\\' && i<chars.length-1)
			{
				i++;
				escaped = true;
			}
			if (chars[i] == '"' && !escaped)
			{
				ret.append(chars, offset+1, i-offset-1);
				return ret.length() + 2;
			}
		}
		throw new IOException("Syntax problem, quoted string has no closing double qote: " + 
				new String(chars, offset, chars.length-offset));
	}
	
	private int eatSpaces(char[] string, int offset, boolean atLeastOne) throws IOException
	{
		int i=0;
		while (i+offset < string.length && string[i+offset] == ' ')
			i++;
		if (atLeastOne && i==0)
			throw new IOException("Syntax problem, expected space character(s) here: " + 
					new String(string, offset, string.length-offset));
		return i;
	}

	public static List<String> normalize(String dn) throws IOException
	{
		List<String> ret = new ArrayList<String>();
		try
		{
			String rfc = CertificateHelpers.opensslToRfc2253(dn, true);
			ret.add(rfc);
			if (dn.endsWith(".*") && !dn.endsWith("/.*"))
				ret.add(".*," + rfc);
			for (int i=0; i<ret.size(); i++)
			{
				rfc = ret.get(i);
				rfc = rfc.replace(".*", "UniqueIdentifier=__qwerty123456789");
				rfc = X500NameUtils.getReadableForm(rfc);
				rfc = rfc.replace("UniqueIdentifier=__qwerty123456789", ".*");
				rfc = rfc.replace("UniqueIdentifier\\=__qwerty123456789", ".*");
				ret.set(i, rfc);
			}
			return ret;
		} catch (Exception e)
		{
			throw new IOException("Subject DN '" + dn + 
					"' has a wrong syntax: ", e);
		}
	}
}









