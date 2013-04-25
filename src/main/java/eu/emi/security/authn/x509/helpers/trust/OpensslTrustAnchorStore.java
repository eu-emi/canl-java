/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.trust;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Timer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;

import eu.emi.security.authn.x509.StoreUpdateListener;
import eu.emi.security.authn.x509.StoreUpdateListener.Severity;
import eu.emi.security.authn.x509.helpers.CertificateHelpers;
import eu.emi.security.authn.x509.helpers.ObserversHandler;
import eu.emi.security.authn.x509.helpers.ns.EuGridPmaNamespacesParser;
import eu.emi.security.authn.x509.helpers.ns.EuGridPmaNamespacesStore;
import eu.emi.security.authn.x509.helpers.ns.GlobusNamespacesParser;
import eu.emi.security.authn.x509.helpers.ns.GlobusNamespacesStore;
import eu.emi.security.authn.x509.helpers.ns.NamespacePolicy;
import eu.emi.security.authn.x509.impl.CertificateUtils.Encoding;

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
			boolean loadEuGridPmaNs, ObserversHandler observers)
	{
		super(Collections.singletonList(basePath+File.separator+CERT_WILDCARD), 
				null, 0, t, updateInterval, Encoding.PEM, observers, true);
		pmaNsStore = new EuGridPmaNamespacesStore();
		globusNsStore = new GlobusNamespacesStore();
		this.loadEuGridPmaNs = loadEuGridPmaNs;
		this.loadGlobusNs = loadGlobusNs;
		update();
		scheduleUpdate();
	}
	
	/**
	 * For all URLs tries to load a CA cert and namespaces
	 */
	@Override
	protected void reloadCerts(Collection<URL> locations)
	{
		List<NamespacePolicy> globus = new ArrayList<NamespacePolicy>();
		List<NamespacePolicy> pma = new ArrayList<NamespacePolicy>();
		Set<TrustAnchorExt> tmpAnchors = new HashSet<TrustAnchorExt>();
		Map<URL, TrustAnchorExt> tmpLoc2anch = new HashMap<URL, TrustAnchorExt>();
		
		for (URL location: locations)
		{
			boolean loaded = tryLoadCert(location, tmpAnchors, tmpLoc2anch);
			if (loaded && loadEuGridPmaNs)
				tryLoadEuGridPmaNs(location, pma);
			if (loaded && loadGlobusNs)
				tryLoadGlobusNs(location, globus);
		}
		
		synchronized(this)
		{
			anchors.addAll(tmpAnchors);
			locations2anchors.putAll(tmpLoc2anch);
			pmaNsStore.setPolicies(pma);
			globusNsStore.setPolicies(globus);
		}
	}
	
	protected boolean tryLoadCert(URL location, Set<TrustAnchorExt> tmpAnchors, Map<URL, TrustAnchorExt> tmpLoc2anch)
	{
		String fileHash = getFileHash(location, CERT_REGEXP);
		if (fileHash == null)
			return false;

		X509Certificate cert;
		try
		{
			cert = loadCert(location);
		} catch (Exception e)
		{
			observers.notifyObservers(location.toExternalForm(), StoreUpdateListener.CA_CERT,
					Severity.ERROR, e);
			return false;
		}
		String certHash = getOpenSSLCAHash(cert.getSubjectX500Principal());
		if (!fileHash.equalsIgnoreCase(certHash))
		{
			//Disabled 'cos of issue #39. Should be reenabled when support for openssl-1.0 hashes is added
			//and modified accordingly
//			observers.notifyObservers(location.toExternalForm(), StoreUpdateListener.CA_CERT, 
//					Severity.WARNING, new Exception("The certificate won't " +
//					"be used as its name has incorrect subject's hash value. Should be " 
//					+ certHash + " but is " + fileHash));
			return false;
		}
		TrustAnchorExt anchor = new TrustAnchorExt(cert, null); 
		tmpAnchors.add(anchor);
		tmpLoc2anch.put(location, anchor);
		return true;
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
			observers.notifyObservers(path, StoreUpdateListener.EACL_NAMESPACE, 
					Severity.NOTIFICATION, null);
		} catch (FileNotFoundException e) {
			//OK - ignored.
		} catch (IOException e)
		{
			observers.notifyObservers(path, StoreUpdateListener.EACL_NAMESPACE, 
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
			observers.notifyObservers(path, StoreUpdateListener.EUGRIDPMA_NAMESPACE, 
					Severity.NOTIFICATION, null);
		} catch (FileNotFoundException e) {
			//OK - ignored.
		} catch (IOException e)
		{
			observers.notifyObservers(path, StoreUpdateListener.EUGRIDPMA_NAMESPACE, 
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
	 * @param name the DN to hash.
	 * @return the 8 character string of the hexadecimal MD5 hash.
	 */
	public static String getOpenSSLCAHash(X500Principal name)
	{
		byte[] bytes = name.getEncoded();
		MD5Digest digest = new MD5Digest();
		digest.update(bytes, 0, bytes.length);
		byte output[] = new byte[digest.getDigestSize()];
		digest.doFinal(output, 0);
		
		return String.format("%02x%02x%02x%02x", output[3] & 0xFF,
				output[2] & 0xFF, output[1] & 0xFF, output[0] & 0xFF);
	}
	
	/**
	 * Generates the hex hash of the DN used by openssl 1.0.0 and above to name the CA
	 * certificate files. The hash is actually the hex of 8 least
	 * significant bytes of a SHA1 digest of the the ASN.1 encoded DN after normalization.
	 * <p>
	 * The normalization is performed as follows:
	 * all strings are converted to UTF8, leading, trailing and multiple spaces collapsed, 
	 * converted to lower case and the leading SEQUENCE header is removed.
	 * 
	 * @param name the DN to hash.
	 * @return the 8 character string of the hexadecimal MD5 hash.
	 */
	public static String getOpenSSLCAHashNew(X500Principal name)
	{
		byte[] bytes;
		try
		{
			RDN[] c19nrdns = getNormalizedRDNs(name);
			bytes = encodeWithoutSeqHeader(c19nrdns);
		} catch (IOException e)
		{
			throw new IllegalArgumentException("Can't parse the input DN", e);
		}
		Digest digest = new SHA1Digest();
		digest.update(bytes, 0, bytes.length);
		byte output[] = new byte[digest.getDigestSize()];
		digest.doFinal(output, 0);
		
		return String.format("%02x%02x%02x%02x", output[3] & 0xFF,
				output[2] & 0xFF, output[1] & 0xFF, output[0] & 0xFF);	
	}
	
	public static RDN[] getNormalizedRDNs(X500Principal name) throws IOException
	{
		X500Name dn = CertificateHelpers.toX500Name(name);
		RDN[] rdns = dn.getRDNs();
		RDN[] c19nrdns = new RDN[rdns.length];
		int i=0;
		for (RDN rdn: rdns)
		{
			AttributeTypeAndValue[] atvs = rdn.getTypesAndValues();
			AttributeTypeAndValue[] c19natvs = new AttributeTypeAndValue[atvs.length];
			for (int j=0; j<atvs.length; j++)
			{
				//TODO - what are the exact types of values that we should treat with this algo?
				String value = IETFUtils.valueToString(atvs[j].getValue());
				value = value.toLowerCase();
				value = value.trim();
				value = value.replaceAll(" [ ]+", " ");
				DERUTF8String newValue = new DERUTF8String(value);
				c19natvs[j] = new AttributeTypeAndValue(atvs[j].getType(), newValue);
			}
			c19nrdns[i++] = new RDN(c19natvs);
		}
		return c19nrdns;
	}
	
	private static byte[] encodeWithoutSeqHeader(RDN[] rdns) throws IOException
	{
	        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
	        ASN1OutputStream      aOut = new ASN1OutputStream(bOut);

		for (RDN rdn: rdns)
		{
			aOut.writeObject(rdn);
		}
		aOut.close();
		return bOut.toByteArray();
	}
}


