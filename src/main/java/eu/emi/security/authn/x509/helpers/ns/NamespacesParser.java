/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.ns;

import java.io.IOException;
import java.util.List;

/**
 * Implemented by namespace parsers.
 * @author K. Benedyczak
 */
public interface NamespacesParser
{
	public List<NamespacePolicy> parse() throws IOException;
}
