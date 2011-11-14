/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.impl;

/**
 * String output mode.
 * @author K. Benedyczak
 */
public enum FormatMode {
	/**
	 * Short form: only subject and issuer are printed, in multiple lines
	 */
	COMPACT,
	
	/**
	 * Medium form: subject, issuer and validity is printed in multiple lines
	 */
	MEDIUM,
	
	/**
	 * Short form: only subject and issuer are printed, in one line
	 */
	COMPACT_ONE_LINE,
	
	/**
	 * Medium form: subject, issuer and validity is printed, in one line
	 */
	MEDIUM_ONE_LINE,

	/**
	 * Most (but not all) of the information that can be read from the 
	 * certificate is included: subject, issuer, validity, fingerprints, usage.
	 * Note that if you want a full dump of the whole certificate contents
	 * then you can use the toString() method of the certificate object.   
	 */
	FULL}