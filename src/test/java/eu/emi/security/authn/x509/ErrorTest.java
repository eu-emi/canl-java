/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509;

import static org.junit.Assert.*;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;

import org.junit.Test;

public class ErrorTest
{
	/**
	 * Checks if all message codes have corresponding enum, if all enums
	 * has corresponding key in properties file and if each code
	 * has a proper category defined.
	 * 
	 * @throws IOException
	 */
	@Test
	public void testMessages() throws IOException
	{
		Properties p = new Properties();
		p.load(ValidationErrorCategory.class.getResourceAsStream(
					"/eu/emi/security/authn/x509/valiadationErrors.properties"));
		
		Set<Object> keys = p.keySet();
		Set<String> categoryPresent = new HashSet<String>();
		Set<String> codePresent = new HashSet<String>();
		for (Object keyO: keys)
		{
			String key = (String) keyO;
			if (key.endsWith(".category"))
			{
				String k = key.substring(0, key.length() - 9);
				String val = p.getProperty(key);
				try
				{
					ValidationErrorCategory.valueOf(val);
				} catch (IllegalArgumentException e)
				{
					fail("Wrong category for key: " + key);
				}
				categoryPresent.add(k);
			} else
			{
				try
				{
					ValidationErrorCode.valueOf(key);
				} catch (IllegalArgumentException e)
				{
					fail("No code in enum for key: " + key);
				}
				codePresent.add(key);
			}
		}
		
		for (String k: codePresent)
		{
			if (!categoryPresent.contains(k))
				fail("No category for " + k);
		}
		
		for (String k: categoryPresent)
		{
			if (!codePresent.contains(k))
				fail("No code for category " + k);
		}
		
		ValidationErrorCode allCodes[] = ValidationErrorCode.values();
		for (ValidationErrorCode code: allCodes)
		{
			if (!codePresent.contains(code.name()))
				fail("No message for code " + code.name());
		}
	}

	@Test
	public void testValidationErrorToString()
	{
		String str = new ValidationError(-1, ValidationErrorCode.unknownMsg, "FOO").toString();
		assertTrue(str.contains("FOO"));
		assertTrue(str.contains("OTHER"));
		assertFalse(str.contains("-1"));
		
		str = new ValidationError(44, ValidationErrorCode.unknownMsg, "FOO").toString();
		assertTrue(str.contains("FOO"));
		assertTrue(str.contains("OTHER"));
		assertTrue(str.contains("44"));
	}
	
	@Test
	public void testValidationResult()
	{
		try
		{
			ValidationResult vr = new ValidationResult(false);
			assertTrue(vr.toString().contains("INVALID"));
			
			vr = new ValidationResult(true);
			assertTrue(vr.toString().contains("VALID") && 
					!vr.toString().contains("INVALID"));
			
			vr = new ValidationResult(false, Collections.singletonList(
					new ValidationError(-1, ValidationErrorCode.unknown)));
			assertEquals(1, vr.getErrors().size());
			assertTrue(vr.toString().contains("INVALID"));
			
			HashSet<String> set = new HashSet<String>();
			set.add("1.2.3");
			vr = new ValidationResult(false, 
					new ArrayList<ValidationError>(), 
					set);
			assertEquals(0, vr.getErrors().size());
			assertEquals(1, vr.getUnresolvedCriticalExtensions().size());
			assertTrue(vr.toString().contains("INVALID"));
			
		} catch (IllegalArgumentException e)
		{
			fail("Got unexpected exception when creating a ValidationResult: " + e);
		}
		
		try
		{
			new ValidationResult(true, null);
			fail("Didn't get the expected exception when creating a ValidationResult");
		} catch (IllegalArgumentException e)
		{
			//EXPECTED, OK
		}
	}
}
