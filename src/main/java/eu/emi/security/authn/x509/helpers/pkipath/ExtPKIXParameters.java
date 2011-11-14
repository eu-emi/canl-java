/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.pkipath;

import java.security.InvalidAlgorithmParameterException;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import eu.emi.security.authn.x509.impl.CrlCheckingMode;

/**
 * Extended PKIX parameters with additional settings related to 
 * the library features different CRL modes and proxy support.
 * @author K. Benedyczak
 */
public class ExtPKIXParameters extends PKIXParameters
{
	protected boolean proxySupport;
	protected CrlCheckingMode crlMode;
	private Set<TrustAnchor> unmodTrustAnchors2;

	public ExtPKIXParameters(Set<TrustAnchor> trustAnchors)
			throws InvalidAlgorithmParameterException
	{
		super(trustAnchors);
		crlMode = CrlCheckingMode.REQUIRE;
		setRevocationEnabled(true);
		proxySupport = false;
	}

	public boolean isProxySupport()
	{
		return proxySupport;
	}

	public void setProxySupport(boolean proxySupport)
	{
		this.proxySupport = proxySupport;
	}

	public CrlCheckingMode getCrlMode()
	{
		return crlMode;
	}

	public void setCrlMode(CrlCheckingMode crlMode)
	{
		this.crlMode = crlMode;
		setRevocationEnabled(crlMode != CrlCheckingMode.IGNORE);
	}

	/**
	 * We override this method as we also accept an empty list of trust anchors.
	 */
	@Override
	public void setTrustAnchors(Set<TrustAnchor> trustAnchors)
			throws InvalidAlgorithmParameterException
	{
		if (trustAnchors == null)
			throw new NullPointerException(
					"the trustAnchors parameters must"
							+ " be non-null");
		for (Iterator<TrustAnchor> i = trustAnchors.iterator(); i.hasNext();)
		{
			if (!(i.next() instanceof TrustAnchor))
				throw new ClassCastException("all elements of set must be "
						+ "of type java.security.cert.TrustAnchor");
		}
		this.unmodTrustAnchors2 = Collections
				.unmodifiableSet(new HashSet<TrustAnchor>(
						trustAnchors));
	}

	/**
	 * Returns an immutable <code>Set</code> of the most-trusted CAs.
	 * 
	 * @return an immutable <code>Set</code> of <code>TrustAnchor</code>s
	 *         (never <code>null</code>)
	 * 
	 * @see #setTrustAnchors
	 */
	@Override
	public Set<TrustAnchor> getTrustAnchors()
	{
		return this.unmodTrustAnchors2;
	}

	@Override
	public String toString()
	{
		String orig = super.toString();
		if (unmodTrustAnchors2 != null)
			orig = orig.replaceFirst("[\n", "[\n  Trust Anchors: " + 
					unmodTrustAnchors2.toString() + "\n");
		return orig;
	}

}
