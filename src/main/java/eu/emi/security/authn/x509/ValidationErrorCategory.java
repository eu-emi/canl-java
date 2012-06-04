/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509;

import java.io.IOException;
import java.util.Properties;

/**
 * This enumeration contains general classes of errors that can be signaled 
 * during certificate path validation. This classification is provided
 * to allow applications to have coarse grained error handling.
 * 
 * 
 * @author K. Benedyczak
 */
public enum ValidationErrorCategory
{
	GENERAL_INPUT,
	INCONSISTENT_PROXY_CHAIN,
	INVALID_PROXY_CERT,
	NAMESPACE,
	X509_BASIC,
	X509_CHAIN,
	POLICY,
	NAME_CONSTRAINT,
	CRL,
	OCSP,
	OTHER;
	
	private static Properties p;
	
	public static ValidationErrorCategory getErrorCategory(ValidationErrorCode code)
	{
		if (p == null)
		{
			p = new Properties();
			try
			{
				p.load(ValidationErrorCategory.class.getResourceAsStream(
						"/eu/emi/security/authn/x509/valiadationErrors.properties"));
			} catch (IOException e)
			{
				throw new RuntimeException("Resource with error codes can not be loaded as a class loader resource, probably library packaging error.", e);
			}
		}

		String category = p.getProperty(code.name() + ".category");
		if (category == null)
			return OTHER;
		try
		{
			return ValidationErrorCategory.valueOf(category);
		} catch (IllegalArgumentException e)
		{
			return OTHER;
		}
	}
}
