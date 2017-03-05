/*
 * Copyright (c) 2017 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers;

/**
 * Provides password on demand.
 * 
 * @author K. Benedyczak
 */
public interface PasswordSupplier
{
	char[] getPassword();
}
