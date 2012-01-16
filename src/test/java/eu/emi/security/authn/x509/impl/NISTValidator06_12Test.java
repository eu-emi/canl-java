/*
 * Copyright (c) 2011 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.impl;

import org.junit.Test;

/**
 * @see http://csrc.nist.gov/groups/ST/crypto_apps_infra/pki/pkitesting.html
 * This file includes tests from seciton 4.6 to 4.12 
 * Sections 8-12 are not yet implemented, and anyway most of them is not applicable as
 * the library doesn't support non-default policy requirements.
 * @author K. Benedyczak
 */
public class NISTValidator06_12Test extends NISTValidatorTestBase
{
	@Test
	public void test4_6_1() throws Exception
	{
		nistTest(1, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "InvalidMissingbasicConstraintsTest1EE", "MissingbasicConstraintsCACert"}, 
		                new String[] { "MissingbasicConstraintsCACRL", TRUST_ANCHOR_ROOT_CRL }, null);
	}
	
	@Test
	public void test4_6_2() throws Exception
	{
		nistTest(1, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "InvalidcAFalseTest2EE", "basicConstraintsCriticalcAFalseCACert"}, 
		                new String[] { "basicConstraintsCriticalcAFalseCACRL", TRUST_ANCHOR_ROOT_CRL }, null);
	}
	
	@Test
	public void test4_6_3() throws Exception
	{
		nistTest(1, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "InvalidcAFalseTest3EE", "basicConstraintsNotCriticalcAFalseCACert"}, 
		                new String[] { "basicConstraintsNotCriticalcAFalseCACRL", TRUST_ANCHOR_ROOT_CRL }, null);
	}
	
	@Test
	public void test4_6_4() throws Exception
	{
		nistTest(0, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "ValidbasicConstraintsNotCriticalTest4EE", "basicConstraintsNotCriticalCACert"}, 
		                new String[] { "basicConstraintsNotCriticalCACRL", TRUST_ANCHOR_ROOT_CRL }, null);
	}
	
	@Test
	public void test4_6_5() throws Exception
	{
		nistTest(1, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "InvalidpathLenConstraintTest5EE", "pathLenConstraint0subCACert", "pathLenConstraint0CACert"}, 
		                new String[] { "pathLenConstraint0subCACRL", "pathLenConstraint0CACRL", TRUST_ANCHOR_ROOT_CRL }, null);
	}
	
	@Test
	public void test4_6_6() throws Exception
	{
		nistTest(1, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "InvalidpathLenConstraintTest6EE", "pathLenConstraint0subCACert", "pathLenConstraint0CACert"}, 
		                new String[] { "pathLenConstraint0subCACRL", "pathLenConstraint0CACRL", TRUST_ANCHOR_ROOT_CRL }, null);
	}
	
	@Test
	public void test4_6_7() throws Exception
	{
		nistTest(0, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "ValidpathLenConstraintTest7EE", "pathLenConstraint0CACert"}, 
		                new String[] { "pathLenConstraint0CACRL", TRUST_ANCHOR_ROOT_CRL }, null);
	}
	
	@Test
	public void test4_6_8() throws Exception
	{
		nistTest(0, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "ValidpathLenConstraintTest8EE", "pathLenConstraint0CACert"}, 
		                new String[] { "pathLenConstraint0CACRL", TRUST_ANCHOR_ROOT_CRL }, null);
	}
	
	@Test
	public void test4_6_9() throws Exception
	{
		nistTest(1, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "InvalidpathLenConstraintTest9EE", "pathLenConstraint6subsubCA00Cert", "pathLenConstraint6subCA0Cert", "pathLenConstraint6CACert"}, 
		                new String[] { "pathLenConstraint6subsubCA00CRL", "pathLenConstraint6subCA0CRL", "pathLenConstraint6CACRL", TRUST_ANCHOR_ROOT_CRL }, null);
	}
	
	@Test
	public void test4_6_10() throws Exception
	{
		nistTest(1, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "InvalidpathLenConstraintTest10EE", "pathLenConstraint6subsubCA00Cert", "pathLenConstraint6subCA0Cert", "pathLenConstraint6CACert"}, 
		                new String[] { "pathLenConstraint6subsubCA00CRL", "pathLenConstraint6subCA0CRL", "pathLenConstraint6CACRL", TRUST_ANCHOR_ROOT_CRL }, null);
	}
	
	@Test
	public void test4_6_11() throws Exception
	{
		nistTest(1, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "InvalidpathLenConstraintTest11EE", "pathLenConstraint6subsubsubCA11XCert", "pathLenConstraint6subsubCA11Cert", "pathLenConstraint6subCA1Cert", "pathLenConstraint6CACert"}, 
		                new String[] { "pathLenConstraint6subsubsubCA11XCRL", "pathLenConstraint6subsubCA11CRL", "pathLenConstraint6subCA1CRL", "pathLenConstraint6CACRL", TRUST_ANCHOR_ROOT_CRL }, null);
	}
	
	@Test
	public void test4_6_12() throws Exception
	{
		nistTest(1, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "InvalidpathLenConstraintTest12EE", "pathLenConstraint6subsubsubCA11XCert", "pathLenConstraint6subsubCA11Cert", "pathLenConstraint6subCA1Cert", "pathLenConstraint6CACert"}, 
		                new String[] { "pathLenConstraint6subsubsubCA11XCRL", "pathLenConstraint6subsubCA11CRL", "pathLenConstraint6subCA1CRL", "pathLenConstraint6CACRL", TRUST_ANCHOR_ROOT_CRL }, null);
	}
	
	@Test
	public void test4_6_13() throws Exception
	{
		nistTest(0, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "ValidpathLenConstraintTest13EE", "pathLenConstraint6subsubsubCA41XCert", "pathLenConstraint6subsubCA41Cert", "pathLenConstraint6subCA4Cert", "pathLenConstraint6CACert"}, 
		                new String[] { "pathLenConstraint6subsubsubCA41XCRL", "pathLenConstraint6subsubCA41CRL", "pathLenConstraint6subCA4CRL", "pathLenConstraint6CACRL", TRUST_ANCHOR_ROOT_CRL }, null);
	}
	
	@Test
	public void test4_6_14() throws Exception
	{
		nistTest(0, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "ValidpathLenConstraintTest14EE", "pathLenConstraint6subsubsubCA41XCert", "pathLenConstraint6subsubCA41Cert", "pathLenConstraint6subCA4Cert", "pathLenConstraint6CACert"}, 
		                new String[] { "pathLenConstraint6subsubsubCA41XCRL", "pathLenConstraint6subsubCA41CRL", "pathLenConstraint6subCA4CRL", "pathLenConstraint6CACRL", TRUST_ANCHOR_ROOT_CRL }, null);
	}

	@Test
	public void test4_6_15() throws Exception
	{
		nistTest(0, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "ValidSelfIssuedpathLenConstraintTest15EE", "pathLenConstraint0SelfIssuedCACert", "pathLenConstraint0CACert"}, 
		                new String[] { "pathLenConstraint0CACRL", TRUST_ANCHOR_ROOT_CRL }, null);
	}
	
	@Test
	public void test4_6_16() throws Exception
	{
		nistTest(1, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "InvalidSelfIssuedpathLenConstraintTest16EE", "pathLenConstraint0subCA2Cert", "pathLenConstraint0SelfIssuedCACert", "pathLenConstraint0CACert"}, 
		                new String[] { "pathLenConstraint0subCA2CRL", "pathLenConstraint0CACRL", TRUST_ANCHOR_ROOT_CRL }, null);
	}
	
	@Test
	public void test4_6_17() throws Exception
	{
		nistTest(0, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "ValidSelfIssuedpathLenConstraintTest17EE", "pathLenConstraint1SelfIssuedsubCACert", "pathLenConstraint1subCACert", "pathLenConstraint1SelfIssuedCACert", "pathLenConstraint1CACert"}, 
		                new String[] { "pathLenConstraint1CACRL", "pathLenConstraint1subCACRL", TRUST_ANCHOR_ROOT_CRL }, null);
	}

	
	
	@Test
	public void test4_7_1() throws Exception
	{
		nistTest(1, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "InvalidkeyUsageCriticalkeyCertSignFalseTest1EE", "keyUsageCriticalkeyCertSignFalseCACert"}, 
		                new String[] { "keyUsageCriticalkeyCertSignFalseCACRL", TRUST_ANCHOR_ROOT_CRL }, null);
	}	

	@Test
	public void test4_7_2() throws Exception
	{
		nistTest(1, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "InvalidkeyUsageNotCriticalkeyCertSignFalseTest2EE", "keyUsageNotCriticalkeyCertSignFalseCACert"}, 
		                new String[] { "keyUsageNotCriticalkeyCertSignFalseCACRL", TRUST_ANCHOR_ROOT_CRL }, null);
	}	

	@Test
	public void test4_7_3() throws Exception
	{
		nistTest(0, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "ValidkeyUsageNotCriticalTest3EE", "keyUsageNotCriticalCACert"}, 
		                new String[] { "keyUsageNotCriticalCACRL", TRUST_ANCHOR_ROOT_CRL }, null);
	}	

	@Test
	public void test4_7_4() throws Exception
	{
		nistTest(1, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "InvalidkeyUsageCriticalcRLSignFalseTest4EE", "keyUsageCriticalcRLSignFalseCACert"}, 
		                new String[] { "keyUsageCriticalcRLSignFalseCACRL", TRUST_ANCHOR_ROOT_CRL }, null);
	}	

	@Test
	public void test4_7_5() throws Exception
	{
		nistTest(1, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "InvalidkeyUsageNotCriticalcRLSignFalseTest5EE", "keyUsageNotCriticalcRLSignFalseCACert"}, 
		                new String[] { "keyUsageNotCriticalcRLSignFalseCACRL", TRUST_ANCHOR_ROOT_CRL }, null);
	}	

	
}
