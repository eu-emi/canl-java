/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.trust;

import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;

public class TrustAnchorExt extends TrustAnchor
{
	public TrustAnchorExt(X509Certificate trustedCert,
			byte[] nameConstraints)
	{
		super(trustedCert, nameConstraints);
	}

	@Override
	public boolean equals(Object o)
	{
		if (!(o instanceof TrustAnchorExt))
			return false;
		TrustAnchorExt other = (TrustAnchorExt) o;
		return getTrustedCert().equals(other.getTrustedCert());
	}
	
	@Override
	public int hashCode()
	{
		return getTrustedCert().hashCode();
	}
}
