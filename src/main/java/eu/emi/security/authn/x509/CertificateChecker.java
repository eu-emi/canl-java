/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509;

import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;

/**
 * Implementation performs low level checks of some certificate properties. 
 * It is intended to be used internally, as a part of certificate chain validation 
 * (so inside {@link X509CertChainValidator} implementation class). 
 * <p>
 * Implementations may be stateful, need not to be thread 
 * safe - one instance must not be used to check two certificate chains 
 * simultaneously. Constructors may need arguments.
 * 
 * @author K. Benedyczak
 */
public interface CertificateChecker
{
	/**
	 * Performs the check(s) on the specified certificate in a chain (possibly 
	 * using its internal state and the rest of chain) and removes any critical 
	 * extensions that it processed from the specified collection of OIDs.
	 * @param certChain certificate chain to get certificate to be checked from
	 * @param position certificate number to be checked
	 * @param unresolvedCritExts collection of yet unresolved, 
	 * critical certificate extensions 
	 * @param unresolvedNonCritExts collection of yet unresolved, 
	 * non critical certificate extensions 
	 * @return list of validation errors. In no errors are found then the list 
	 * shall be empty. Null is never returned. 
	 */
	public List<ChainValidationError> check(X509Certificate[] certChain, int position, 
			Collection<String> unresolvedCritExts, 
			Collection<String> unresolvedNonCritExts);
	/**
	 * Performs any initialization that is required to start checking 
	 * of a new certificate chain.   
	 */
	public void init();
}
