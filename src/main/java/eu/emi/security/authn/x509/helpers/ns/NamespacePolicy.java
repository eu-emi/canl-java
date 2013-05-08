/*
 * Copyright (c) 2011 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.ns;

import javax.security.auth.x500.X500Principal;


/**
 * Represents a namespace policy, i.e. defines which subject DNs are permitted or denied for an issuer.
 * @author K. Benedyczak
 */
public interface NamespacePolicy
{
	/**
	 * @return the issuer
	 */
	public String getIssuer();

	/**
	 * @return whether the policy is permit or deny
	 */
	public boolean isPermit();

	/**
	 * @return the identification
	 */
	public String getIdentification();
	
	/**
	 * @return hash of the CA where the policy is defined. It can be the  
	 * {@link #getIssuer()} hash or it may be its parent CA subject name hash, if the namespace was defined in 
	 * its namespaces file.
	 */
	public String getDefinedFor();
	
	/**
	 * Checks whether the given subject name is matching this policy.
	 * @param subject to be checked
	 * @return true if subject is matched, false otherwise
	 */
	public boolean isSubjectMatching(X500Principal subject);
}










