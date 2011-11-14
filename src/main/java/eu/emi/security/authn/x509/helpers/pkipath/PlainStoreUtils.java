/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.pkipath;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.filefilter.WildcardFileFilter;
import org.bouncycastle.util.encoders.Base64;

import eu.emi.security.authn.x509.impl.CertificateUtils;

/**
 * Class for CA or CRL stores with utility methods for handling list 
 * of locations as wildcards or URLs.
 * @author K. Benedyczak
 */
public class PlainStoreUtils
{
	private String diskPath;
	private String suffix;
	private final List<String> srcLocations;
	private final List<String> wildcardLocations;
	private final List<URL> urlLocations;
	private List<URL> resolvedWildcardLocations;
	
	
	public PlainStoreUtils(String diskPath, String suffix, List<String> locations)
	{
		this.diskPath = diskPath;
		this.suffix = suffix;
		wildcardLocations = new ArrayList<String>();
		urlLocations = new ArrayList<URL>();
		resolvedWildcardLocations = new ArrayList<URL>();
		srcLocations = locations;
		for (String s: srcLocations)
		{
			try
			{
				URL u = new URL(s);
				urlLocations.add(u);
			} catch (MalformedURLException e)
			{
				wildcardLocations.add(s);
			}
		}
	}
	
	public File getCacheFile(URL url) 
			throws URISyntaxException
	{
		File dir = new File(diskPath);
		byte[] src = url.toURI().toASCIIString().getBytes();
		byte[] encoded = Base64.encode(src);
		String filename = new String(encoded,CertificateUtils.ASCII) + 
				suffix + ".der";
		return new File(dir, filename);
	}

	public void saveCacheFile(byte[] what, URL url) 
			throws URISyntaxException, IOException
	{
		if (diskPath == null)
			return;
		File output = getCacheFile(url);
		OutputStream os = new BufferedOutputStream(
				new FileOutputStream(output));
		os.write(what);
		os.close();
	}
	
	/**
	 * resolves one wildcard and add results to the resolvedWildcardLocations list
	 * @param wildcard
	 */
	private void establishWildcardLocations(String wildcard)
	{
		File f = new File(wildcard);
		File base = f.getParentFile();
		Collection<File> files = FileUtils.listFiles(base, 
				new WildcardFileFilter(f.getName()), null);
		for (File file: files)
			try
			{
				resolvedWildcardLocations.add(file.toURI().toURL());
			} catch (MalformedURLException e)
			{
				throw new RuntimeException("Can't convert File to URL?", e);
			}
	}
	
	/**
	 * resolves all wildcards
	 */
	public void establishWildcardsLocations()
	{
		resolvedWildcardLocations.clear();
		for (String loc: wildcardLocations)
		{
			establishWildcardLocations(loc);
		}
	}

	public boolean isPresent(URL u)
	{
		return urlLocations.contains(u) || resolvedWildcardLocations.contains(u);
	}
	
	public List<URL> getResolvedWildcards()
	{
		return resolvedWildcardLocations;
	}

	public List<URL> getURLLocations()
	{
		return urlLocations;
	}
	
	public List<String> getLocations()
	{
		List<String> ret = new ArrayList<String>(srcLocations.size());
		ret.addAll(srcLocations);
		return ret;
	}
}
