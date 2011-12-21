/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.trust;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Timer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.crypto.digests.MD5Digest;

import eu.emi.security.authn.x509.StoreUpdateListener;
import eu.emi.security.authn.x509.StoreUpdateListener.Severity;
import eu.emi.security.authn.x509.helpers.ns.EuGridPmaNamespacesParser;
import eu.emi.security.authn.x509.helpers.ns.EuGridPmaNamespacesStore;
import eu.emi.security.authn.x509.helpers.ns.GlobusNamespacesParser;
import eu.emi.security.authn.x509.helpers.ns.GlobusNamespacesStore;
import eu.emi.security.authn.x509.helpers.ns.NamespacePolicy;

/**
 * Implementation of the truststore which uses CA certificates from a single directory 
 * in OpenSSL format. Each certificate should be stored in a file named HASH.NUM,
 * where HASH is an 8 digit hex number, with 8 least significant digits of the MD5
 * hash of the certificate subject in DER format. The NUM must be a number, starting from 0.
 * <p>
 * This class is extending the {@link DirectoryTrustAnchorStore} and restricts 
 * the certificates which are loaded.
 * 
 * @author K. Benedyczak
 */
public class OpensslTrustAnchorStore extends DirectoryTrustAnchorStore
{
	public static final String CERT_WILDCARD = "????????.*";
	public static final String CERT_REGEXP = "^([0-9a-fA-F]{8})\\.[\\d]+$";
	private boolean loadEuGridPmaNs;
	private boolean loadGlobusNs;
	private EuGridPmaNamespacesStore pmaNsStore;
	private GlobusNamespacesStore globusNsStore;
	
	public OpensslTrustAnchorStore(String basePath,	Timer t, long updateInterval, boolean loadGlobusNs,
			boolean loadEuGridPmaNs, Collection<? extends StoreUpdateListener> listeners)
	{
		super(Collections.singletonList(basePath+File.separator+CERT_WILDCARD), 
				null, 0, t, updateInterval, listeners, true);
		pmaNsStore = new EuGridPmaNamespacesStore();
		globusNsStore = new GlobusNamespacesStore();
		this.loadEuGridPmaNs = loadEuGridPmaNs;
		this.loadGlobusNs = loadGlobusNs;
		update();
	}
	
	/**
	 * For all URLs tries to load a CA cert and namespaces
	 */
	@Override
	protected void reloadCerts(Collection<URL> locations)
	{
		List<NamespacePolicy> globus = new ArrayList<NamespacePolicy>();
		List<NamespacePolicy> pma = new ArrayList<NamespacePolicy>();
		for (URL location: locations)
		{
			tryLoadCert(location);
			if (loadEuGridPmaNs)
				tryLoadEuGridPmaNs(location, pma);
			if (loadGlobusNs)
				tryLoadGlobusNs(location, globus);
		}
		pmaNsStore.setPolicies(pma);
		globusNsStore.setPolicies(globus);
	}
	
	protected void tryLoadCert(URL location)
	{
		String fileHash = getFileHash(location, CERT_REGEXP);
		if (fileHash == null)
			return;

		X509Certificate cert;
		try
		{
			cert = loadCert(location);
		} catch (Exception e)
		{
			notifyObservers(location.toExternalForm(), StoreUpdateListener.CA_CERT,
					Severity.ERROR, e);
			return;
		}
		String certHash = getOpenSSLCAHash(cert.getSubjectX500Principal());
		if (!fileHash.equalsIgnoreCase(certHash))
		{
			notifyObservers(location.toExternalForm(), StoreUpdateListener.CA_CERT, 
					Severity.WARNING, new Exception("The certificate won't " +
					"be used as its name has incorrect subject's hash value. Should be " 
					+ certHash + " but is " + fileHash));
			return;
		}
		notifyObservers(location.toExternalForm(), StoreUpdateListener.CA_CERT,
				Severity.NOTIFICATION, null);
		TrustAnchorExt anchor = new TrustAnchorExt(cert, null); 
		anchors.add(anchor);
		locations2anchors.put(location, anchor);
	}
	
	public EuGridPmaNamespacesStore getPmaNsStore()
	{
		return pmaNsStore;
	}

	public GlobusNamespacesStore getGlobusNsStore()
	{
		return globusNsStore;
	}

	protected void tryLoadGlobusNs(URL location, List<NamespacePolicy> globus)
	{
		String path = getNsFile(location, ".signing_policy");
		if (path == null)
			return;
		GlobusNamespacesParser parser = new GlobusNamespacesParser(path);
		try
		{
			globus.addAll(parser.parse());
			notifyObservers(path, StoreUpdateListener.EACL_NAMESPACE, 
					Severity.NOTIFICATION, null);
		} catch (FileNotFoundException e) {
			//OK - ignored.
		} catch (IOException e)
		{
			notifyObservers(path, StoreUpdateListener.EACL_NAMESPACE, 
					Severity.ERROR, e);
		}
	}

	protected void tryLoadEuGridPmaNs(URL location, List<NamespacePolicy> list)
	{
		String path = getNsFile(location, ".namespaces");
		if (path == null)
			return;
		EuGridPmaNamespacesParser parser = new EuGridPmaNamespacesParser(path);
		try
		{
			list.addAll(parser.parse());
			notifyObservers(path, StoreUpdateListener.EUGRIDPMA_NAMESPACE, 
					Severity.NOTIFICATION, null);
		} catch (FileNotFoundException e) {
			//OK - ignored.
		} catch (IOException e)
		{
			notifyObservers(path, StoreUpdateListener.EUGRIDPMA_NAMESPACE, 
					Severity.ERROR, e);
		}
	}

	private String getNsFile(URL certLocation, String suffix)
	{
		String fileHash = getFileHash(certLocation, CERT_REGEXP);
		if (fileHash == null)
			return null;
		File f = new File(certLocation.getPath());
		String parent = f.getParent();
		if (parent == null)
			parent = ".";
		return parent + File.separator + fileHash + suffix;
	}
	
	public static String getFileHash(URL location, String regexp)
	{
		return getFileHash(location.getPath(), regexp);
	}

	public static String getFileHash(String path, String regexp)
	{
		File f = new File(path);
		String name = f.getName();
		Pattern pattern = Pattern.compile(regexp);
		Matcher m = pattern.matcher(name);
		if (!m.matches())
			return null;
		return m.group(1);
	}
	
	/**
	 * Generates the hex hash of the DN used by openssl to name the CA
	 * certificate files. The hash is actually the hex of 8 least
	 * significant bytes of a MD5 digest of the the ASN.1 encoded DN.
	 * 
	 * @param subject the DN to hash.
	 * @return the 8 character string of the hexadecimal hash.
	 */
	public static String getOpenSSLCAHash(X500Principal name)
	{
		byte[] bytes = name.getEncoded();
		MD5Digest digest = new MD5Digest();
		digest.update(bytes, 0, bytes.length);
		byte output[] = new byte[16];
		digest.doFinal(output, 0);
		return String.format("%02x%02x%02x%02x", output[3] & 0xFF,
				output[2] & 0xFF, output[1] & 0xFF, output[0] & 0xFF);
	}
}
