/*
 * Copyright (c) 2011 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.helpers;

import java.io.IOException;
import java.io.Reader;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.openssl.PasswordFinder;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.io.pem.PemHeader;
import org.bouncycastle.util.io.pem.PemObject;


/**
 * Extends BC's {@link PEMReader} class so it can read correctly also 
 * PEM files with a garbage at the beginning 
 * and minor syntax violations which occur more then often in the wild. 
 *
 * @author K. Benedyczak
 */
public class FlexiblePEMReader extends PEMReader
{
	/**
	 * {@inheritDoc}
	 */
	public FlexiblePEMReader(Reader reader)
	{
		super(reader);
	}

	/**
	 * {@inheritDoc}
	 */
	public FlexiblePEMReader(Reader reader, PasswordFinder pFinder,
			String symProvider, String asymProvider)
	{
		super(reader, pFinder, symProvider, asymProvider);
	}

	/**
	 * {@inheritDoc}
	 */
	public FlexiblePEMReader(Reader reader, PasswordFinder pFinder,
			String provider)
	{
		super(reader, pFinder, provider);
	}

	/**
	 * {@inheritDoc}
	 */
	public FlexiblePEMReader(Reader reader, PasswordFinder pFinder)
	{
		super(reader, pFinder);
	}
	
	/**
	 * Generate BC's PemObject
	 * @return the parsed PEM object
	 * @throws IOException
	 */
	@Override
	public PemObject readPemObject() throws IOException
	{
		Pattern starter = Pattern.compile("^---[-]+BEGIN [^-]+---[-]+$");
		Pattern end = Pattern.compile("^---[-]+END [^-]+---[-]+$");
		
		String line;
		boolean startFound = false;
		while ((line=readLine()) != null)
		{
			Matcher m = starter.matcher(line);
			if (m.find())
			{
				startFound = true;
				break;
			}
		}
		if (!startFound)
			return null;
		
		int pos = line.indexOf("BEGIN ") + 6;
	        int endPos = line.indexOf('-', pos);
	        String type = line.substring(pos, endPos);
		
		boolean endFound = false;
		StringBuilder sb = new StringBuilder();
		List<PemHeader> headers = new ArrayList<PemHeader>();
		while ((line=readLine()) != null)
		{
			Matcher m = end.matcher(line);
			if (m.find())
				throw new IOException("The supplied data is not in PEM format, end line found before getting any contents.");
			if (line.indexOf(":") >= 0)
			{
		                int index = line.indexOf(':');
		                String hdr = line.substring(0, index);
		                String value = line.substring(index + 1).trim();
		                headers.add(new PemHeader(hdr, value));
			} else 
			{
				sb.append(line.trim());
				break;
			}
		}
		
		while ((line=readLine()) != null)
		{
			Matcher m = end.matcher(line);
			if (m.find())
			{
				endFound = true;
				break;
			} else 
				sb.append(line.trim());
		}
		if (!endFound)
			throw new IOException("The supplied data is not in PEM format, no ending line found.");

		return new PemObject(type, headers, Base64.decode(sb.toString()));
	}

}
