/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;


/**
 * Wraps a validation result, error messages and unresolved 
 * certificate extension oids (if any).
 * 
 * @author K. Benedyczak
 * @see X509CertChainValidator
 */
public class ValidationResult
{
	private boolean valid;
	private List<ValidationError> errors;
	private Set<String> unresolvedCriticalExtensions;

	/**
	 * Constructor used when no errors are provided and no information about unresolved extensions.
	 * @param valid whether validation was valid (true) or not (false).
	 */
	public ValidationResult(boolean valid)
	{
		this(valid, new ArrayList<ValidationError>(0));
	}

	/**
 	 * Constructor used when no information about unresolved extensions is provided.
	 * @param valid whether validation was valid (true) or not (false).
	 * @param errors list of errors found
	 */
	public ValidationResult(boolean valid, List<ValidationError> errors)
	{
		this(valid, errors, new HashSet<String>(0));
	}

	/**
 	 * Constructor used to provide a full information set about validation problem.
	 * @param valid whether validation was valid (true) or not (false).
	 * @param errors list of errors found
	 * @param unresolvedCriticalExtensions set of unresolved critical extensions
	 */
	public ValidationResult(boolean valid, List<ValidationError> errors, 
			Set<String> unresolvedCriticalExtensions)
	{
		this.valid = valid;
		this.errors = errors;
		this.unresolvedCriticalExtensions = unresolvedCriticalExtensions;
		if (errors == null)
			throw new IllegalArgumentException("List of validation errors can not be null");
		if (unresolvedCriticalExtensions == null)
			throw new IllegalArgumentException("Set of unresolved critical extensions can not be null");
	}
	
	/**
	 * Adds specified errors to this result (may change valid flag).
	 * @param errors to be added
	 */
	public void addErrors(List<ValidationError> errors)
	{
		if (errors.size() > 0)
			valid = false;
		this.errors.addAll(errors);
	}
	
	/**
	 * Returns whether validation was successful or not.
	 * @return true if the validated chain turned out to be valid, false otherwise. 
	 */
	public boolean isValid()
	{
		return valid;
	}

	/**
	 * Returns list of problems found. Empty list is returned if certificate chain 
	 * is valid.
	 * @return list of {@link ValidationError}s
	 */
	public List<ValidationError> getErrors()
	{
		return errors;
	}

	/**
	 * Returns a set of unresolved critical certificate extensions. 
	 * @return set of unresolved critical extensions OIDs in String form
	 */
	public Set<String> getUnresolvedCriticalExtensions()
	{
		return unresolvedCriticalExtensions;
	}

	/**
	 * 
	 * @return a short representation of validation result, which will contain 
	 * only one (hopefully the most significant) validation error description.
	 */
	public String toShortString()
	{
		if (valid)
			return "OK";
		StringBuilder sb = new StringBuilder();
		sb.append("FAILED");

		if (errors.size() > 0)
		{
			for (ValidationError e: errors)
				if (e.getPosition() == -1)
				{
					sb.append(": " + e.getMessage());
					return sb.toString();
				}
			sb.append(": " + errors.get(0).getMessage());
		}
		return sb.toString();
	}	
	
	/**
	 * @return a full (multiline) representation of validation result, including
	 * detailed information about all validation errors found.
	 */
	@Override
	public String toString()
	{
		if (valid)
			return "OK";
		StringBuilder sb = new StringBuilder();
		sb.append("FAILED");
		if (errors.size() > 0)
		{
			sb.append(" The following validation errors were found:");
			for (ValidationError e: errors)
			{
				sb.append("\n");
				sb.append(e.toString());
			}
		}
		return sb.toString();
	}
}
