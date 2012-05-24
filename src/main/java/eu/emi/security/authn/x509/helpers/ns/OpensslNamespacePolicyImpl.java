/*
 * Copyright (c) 2011 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.ns;

import java.util.regex.Pattern;

import javax.security.auth.x500.X500Principal;

import eu.emi.security.authn.x509.impl.OpensslNameUtils;


/**
 * Represents a namespace policy, i.e. defines which subject DNs are permitted or denied for an issuer.
 * @author K. Benedyczak
 */
public class OpensslNamespacePolicyImpl implements NamespacePolicy
{
	private String issuer;
	private String subject;
	private String identification;
	private boolean permit;
	private Pattern pattern;
	
	public OpensslNamespacePolicyImpl(String issuer, String subject, boolean permit, String identification)
	{
		this.issuer = issuer;
		this.identification = identification;
		this.subject = subject;
		this.permit = permit;
		this.pattern = Pattern.compile(this.subject, Pattern.CASE_INSENSITIVE);
	}

	/**
	 * @return the issuer
	 */
	@Override
	public String getIssuer()
	{
		return issuer;
	}

	/**
	 * @return the subject
	 */
	public String getSuject()
	{
		return subject;
	}

	/**
	 * @return whether the policy is permit or deny
	 */
	@Override
	public boolean isPermit()
	{
		return permit;
	}

	/**
	 * @return the identification
	 */
	@Override
	public String getIdentification()
	{
		return identification;
	}
	
	/**
	 * Checks whether the given subject name is matching this policy.
	 * @param subject to be checked
	 * @return true if subject is matched, false otherwise
	 */
	@Override
	public boolean isSubjectMatching(X500Principal subject)
	{
		String opensslDn = OpensslNameUtils.convertFromRfc2253(subject.getName(), false);
		String normalized = OpensslNameUtils.normalize(opensslDn);
		return pattern.matcher(normalized).matches();
	}

}


