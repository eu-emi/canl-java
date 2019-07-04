/*
 * Copyright (c) 2019 Bixbit - Krzysztof Benedyczak. All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.pkipath;

import static org.junit.Assert.fail;

import java.util.Collections;

import org.junit.Test;

public class PlainStoreUtilsTest
{
	@Test
	public void shouldAcceptRelativeFileWithoutParent()
	{
		PlainStoreUtils storeUtils = new PlainStoreUtils("", "", Collections.singletonList("pom.xml"));
		
		try
		{
			storeUtils.establishWildcardsLocations();
		} catch (Exception e)
		{
			e.printStackTrace();
			fail("Shouldn't get exception");
		}
	}
}
