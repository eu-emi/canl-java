/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509;

import java.io.InputStream;
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
	
	private static Properties p = null;

        private static final String RESOURCE_NAME = "/eu/emi/security/authn/x509/valiadationErrors.properties";

        private static void setErrorProperties() {
            InputStream is = null;
            try {
                is = ValidationErrorCategory.class.getResourceAsStream(RESOURCE_NAME);

                Properties properties = new Properties();
                properties.load(is);
                p = properties;  // set field AFTER properties are fully constructed

            } catch (IOException e) {
                p = new Properties();  // use empty properties on error
                throw new RuntimeException("Resource with error codes can not be loaded as a class loader resource, probably library packaging error.", e);
            } finally {
                if (is != null) {
                    try {
                        is.close();
                    } catch (IOException consumed) {
                    }
                }
            }
        }

	public static ValidationErrorCategory getErrorCategory(ValidationErrorCode code)
	{
		if (p == null)
		{
                    setErrorProperties();
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
