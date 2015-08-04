/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.trust;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.WeakHashMap;

import javax.security.auth.x500.X500Principal;

import eu.emi.security.authn.x509.StoreUpdateListener;
import eu.emi.security.authn.x509.StoreUpdateListener.Severity;
import eu.emi.security.authn.x509.helpers.CachedElement;
import eu.emi.security.authn.x509.helpers.ObserversHandler;
import eu.emi.security.authn.x509.helpers.ns.LazyEuGridPmaNamespacesStore;
import eu.emi.security.authn.x509.helpers.ns.LazyGlobusNamespacesStore;
import eu.emi.security.authn.x509.helpers.ns.NamespacesStore;
import eu.emi.security.authn.x509.impl.CertificateUtils;
import eu.emi.security.authn.x509.impl.CertificateUtils.Encoding;
import eu.emi.security.authn.x509.impl.X500NameUtils;

/**
 * Implementation of the truststore which uses CA certificates from a single directory 
 * in OpenSSL format. Each certificate should be stored in a file named HASH.NUM,
 * where HASH is an 8 digit hex number. The NUM must be a number, starting from 0.
 * The hash can be either of openssl pre 1.0.0 version 
 * (with 8 least significant digits of the MD5 hash of the certificate subject in DER format)
 * or in openssl 1.0.0 and above format (SHA1 hash of specially normalized DN). The class is configured
 * to use one or another, never both.
 * <p>
 * This class (contrary to the {@link OpensslTrustAnchorStoreImpl}) doesn't extend {@link DirectoryTrustAnchorStore} 
 * and therefore certificates (and all corresponding files) are not loaded at startup and kept in memory.
 * The files are loaded on-demand and are only cached in memory for no longer then the updateInterval is. 
 * 
 * @author K. Benedyczak
 */
public class LazyOpensslTrustAnchorStoreImpl extends AbstractTrustAnchorStore implements OpensslTrustAnchorStore
{
	public static final String CERTS_REGEXP = "........\\.[0-9]+";
	protected CachedElement<Set<TrustAnchorExt>> cachedAnchors;
	protected Map<X500Principal, CachedElement<Set<TrustAnchorExt>>> cachedAnchorsPerIssuer;
	private boolean openssl1Mode;
	private NamespacesStore pmaNsStore;
	private NamespacesStore globusNsStore;
	private File baseDirectory;
	
	public LazyOpensslTrustAnchorStoreImpl(String basePath, long updateInterval, 
			ObserversHandler observers, boolean openssl1Mode)
	{
		super(updateInterval, observers);
		this.baseDirectory = new File(basePath);
		this.openssl1Mode = openssl1Mode;
		this.cachedAnchorsPerIssuer = new WeakHashMap<X500Principal, CachedElement<Set<TrustAnchorExt>>>(150);
		pmaNsStore = new LazyEuGridPmaNamespacesStore(observers, openssl1Mode, basePath, updateInterval);
		globusNsStore = new LazyGlobusNamespacesStore(observers, openssl1Mode, basePath, updateInterval);
	}
	
	protected X509Certificate tryLoadCertInternal(File file)
	{
		X509Certificate cert;
		try
		{
			InputStream is = new BufferedInputStream(new FileInputStream(file));
			cert = CertificateUtils.loadCertificate(is, Encoding.PEM);
			observers.notifyObservers(file.getAbsolutePath(),
					StoreUpdateListener.CA_CERT,
					Severity.NOTIFICATION, null);
			return cert;
		} catch (Exception e)
		{
			observers.notifyObservers(file.getAbsolutePath(), StoreUpdateListener.CA_CERT,
					Severity.ERROR, e);
			return null;
		}
	}
	
	protected void tryLoadCert(File file, Set<TrustAnchorExt> set)
	{
		String fileHash = OpensslTruststoreHelper.getFileHash(file.getPath(), 
				OpensslTruststoreHelper.CERT_REGEXP);
		if (fileHash == null)
			return;

		X509Certificate cert = tryLoadCertInternal(file);
		if (cert == null)
			return;

		String certHash = OpensslTruststoreHelper.getOpenSSLCAHash(cert.getSubjectX500Principal(), openssl1Mode);
		if (!fileHash.equalsIgnoreCase(certHash))
			return;

		TrustAnchorExt anchor = new TrustAnchorExt(cert, null);
		set.add(anchor);
	}
	
	
	@Override
	public NamespacesStore getPmaNsStore()
	{
		return pmaNsStore;
	}

	@Override
	public NamespacesStore getGlobusNsStore()
	{
		return globusNsStore;
	}

	private Set<TrustAnchorExt> loadTrustAnchors()
	{
		Collection<File> certs = OpensslTruststoreHelper.getFilesWithRegexp(CERTS_REGEXP, baseDirectory);
		Set<TrustAnchorExt> ret = new HashSet<TrustAnchorExt>(certs.size());
		for (File cert: certs)
			tryLoadCert(cert, ret);
		return ret;
	}
	
	@Override
	public Set<TrustAnchor> getTrustAnchors()
	{
		if (cachedAnchors == null || cachedAnchors.isExpired(getUpdateInterval()))
		{
			Set<TrustAnchorExt> loaded = loadTrustAnchors();
			cachedAnchors = new CachedElement<Set<TrustAnchorExt>>(loaded);
		}
		Set<TrustAnchor> ret = new HashSet<TrustAnchor>();
		ret.addAll(cachedAnchors.getElement());
		return ret;
	}

	@Override
	public X509Certificate[] getTrustedCertificates()
	{
		Set<TrustAnchor> anchors = getTrustAnchors();
		X509Certificate[] ret = new X509Certificate[anchors.size()];
		int i=0;
		for (TrustAnchor ta: anchors)
			ret[i++] = ta.getTrustedCert();
		return ret;
	}

	@Override
	public void dispose()
	{
	}
	
	/**
	 * Algorithm is as follows: for each certificate subject in chain, and for the issuer of the last 
	 * certificate in chain, it is tried to load a trust anchor defined for such subject. If successful
	 * then also it is tried recursively to load all parent trust anchors for the loaded one.
	 *  
	 * @param certChain certificate chain
	 * @return set of trust anchors for a given certificate chain
	 */
	public Set<TrustAnchor> getTrustAnchorsFor(X509Certificate[] certChain)
	{
		Set<TrustAnchorExt> ret = new HashSet<TrustAnchorExt>();
		for (X509Certificate c: certChain)
		{
			tryLoadTAFor(c.getSubjectX500Principal(), ret);
		}
		tryLoadTAFor(certChain[certChain.length-1].getIssuerX500Principal(), ret);
		
		return new HashSet<TrustAnchor>(ret);
	}
	
	private void tryLoadTAFor(X500Principal issuer, Set<TrustAnchorExt> ret)
	{
		CachedElement<Set<TrustAnchorExt>> cached = cachedAnchorsPerIssuer.get(issuer);
		if (cached != null && !cached.isExpired(updateInterval))
		{
			ret.addAll(cached.getElement());
			return;
		}
		Set<TrustAnchorExt> toCache = new HashSet<TrustAnchorExt>();
		String hash = OpensslTruststoreHelper.getOpenSSLCAHash(issuer, openssl1Mode);
		Collection<File> certs = OpensslTruststoreHelper.getFilesWithRegexp(hash+"\\.[0-9]+", baseDirectory);
		for (File file: certs)
		{
			X509Certificate cert = tryLoadCertInternal(file);
			if (X500NameUtils.rfc3280Equal(cert.getSubjectX500Principal(), issuer))
			{
				toCache.add(new TrustAnchorExt(cert, null));
				X500Principal certIssuer = cert.getIssuerX500Principal();
				if (!X500NameUtils.rfc3280Equal(certIssuer, issuer))
					tryLoadTAFor(certIssuer, toCache);
			}
		}
		
		ret.addAll(toCache);
		cachedAnchorsPerIssuer.put(issuer, new CachedElement<Set<TrustAnchorExt>>(toCache));
	}
}


