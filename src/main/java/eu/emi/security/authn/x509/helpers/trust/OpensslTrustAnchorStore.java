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

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERT61String;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.DERUniversalString;
import org.bouncycastle.asn1.DERVisibleString;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
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
 * where HASH is an 8 digit hex number. The NUM must be a number, starting from 0.
 * THe hash can be either of openssl pre 1.0.0 version 
 * (with 8 least significant digits of the MD5 hash of the certificate subject in DER format)
 * or in openssl 1.0.0 and above format (SHA1 hash of specially normalized DN).
 * <p>
 * The openssl 1.0.0 form is tried first, so it is suggested.
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

		String certHash = getOpenSSLCAHashNew(cert.getSubjectX500Principal());
		String certHashNew = certHash;
		boolean oldHash = false;
		if (!fileHash.equalsIgnoreCase(certHash))
		{
			certHash = getOpenSSLCAHash(cert.getSubjectX500Principal());
			oldHash = true;
		}
		
		if (!fileHash.equalsIgnoreCase(certHash))
		{
			observers.notifyObservers(location.toExternalForm(), StoreUpdateListener.CA_CERT, 
					Severity.WARNING, new Exception("The certificate won't " +
					"be used as its name has incorrect subject's hash value. Should be " 
					+ certHashNew + " or " + certHash + " (legacy) but is " + fileHash));
			return false;
		}
		TrustAnchorExt anchor = new TrustAnchorExt(cert, null);
		if (!oldHash || !tmpAnchors.contains(anchor))
		{
			tmpAnchors.add(anchor);
			tmpLoc2anch.put(location, anchor);
			return true;
		}
		return false; //old hash and we already had such in store
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
			sortAVAs(atvs);
			AttributeTypeAndValue[] c19natvs = new AttributeTypeAndValue[atvs.length];
			for (int j=0; j<atvs.length; j++)
			{
				c19natvs[j] = normalizeStringAVA(atvs[j]);
			}
			c19nrdns[i++] = new RDN(c19natvs);
		}
		return c19nrdns;
	}
	
	private static void sortAVAs(AttributeTypeAndValue[] atvs) throws IOException
	{
		for (int i=0; i<atvs.length; i++)
			for (int j=i+1; j<atvs.length; j++)
			{
				if (memcmp(atvs[i].getEncoded(), atvs[j].getEncoded()) < 0)
				{
					AttributeTypeAndValue tmp = atvs[i];
					atvs[i] = atvs[j];
					atvs[j] = tmp;
				}
			}
	}
	
	private static int memcmp(byte[] a, byte[] b)
	{
		int min = a.length > b.length ? b.length : a.length;
		for (int i=0; i<min; i++)
			if (a[i] < b[i])
				return -1;
			else if (a[i] > b[i])
				return 1;
		return a.length - b.length;
	}
	
	private static AttributeTypeAndValue normalizeStringAVA(AttributeTypeAndValue src)
	{
		ASN1Encodable srcVal = src.getValue();
		if (	!((srcVal instanceof DERPrintableString) ||
			(srcVal instanceof DERUTF8String) ||
			(srcVal instanceof DERIA5String) ||
			(srcVal instanceof DERBMPString) ||
			(srcVal instanceof DERUniversalString) ||
			(srcVal instanceof DERT61String) ||
			(srcVal instanceof DERVisibleString)))
			return src;
		ASN1String srcString = (ASN1String) srcVal;
		String value = srcString.getString();
		value = value.trim();
		value = value.replaceAll("[ \t\n\f][ \t\n\f]+", " ");
		value = value.toLowerCase();
		DERUTF8String newValue = new DERUTF8String(value);
		return new AttributeTypeAndValue(src.getType(), newValue);
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


