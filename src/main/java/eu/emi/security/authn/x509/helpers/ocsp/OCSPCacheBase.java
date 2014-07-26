/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.ocsp;

import java.io.File;
import java.nio.charset.Charset;
import java.security.MessageDigest;

import org.bouncycastle.util.encoders.Base64;



/**
 * Common base class for responses and responders caches.
 * 
 * @author K. Benedyczak
 */
public abstract class OCSPCacheBase
{
	protected static final Charset ASCII = Charset.forName("US-ASCII");
	protected final long maxTtl;
	protected final File diskPath;
	protected final String prefix;
	
	public OCSPCacheBase(long maxTtl, File diskPath, String prefix)
	{
		this.maxTtl = maxTtl;
		this.diskPath = diskPath;
		this.prefix = (prefix == null) ? "" : prefix;
	}

	protected String encodeDigest(MessageDigest digest)
	{
		byte[] shortBytes = digest.digest();
		byte[] ascii = Base64.encode(shortBytes);
		String ret = new String(ascii, ASCII);
		return ret.replace('/', '_');
	}
}









