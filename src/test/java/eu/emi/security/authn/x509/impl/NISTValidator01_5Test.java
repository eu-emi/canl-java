/*
 * Copyright (c) 2011 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.impl;

import org.junit.Test;

/**
 * @see http://csrc.nist.gov/groups/ST/crypto_apps_infra/pki/pkitesting.html
 * This file includes tests from seciton 4.1 to 4.5 
 * @author K. Benedyczak
 */
public class NISTValidator01_5Test extends NISTValidatorTestBase
{
	@Test
	public void test4_1_1() throws Exception
	{
		nistTest(0, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "ValidCertificatePathTest1EE", GOOD_CA_CERT}, 
		                new String[] { GOOD_CA_CRL, TRUST_ANCHOR_ROOT_CRL }, null);
	}

	@Test
	public void test4_1_2() throws Exception
	{
		nistTest(2, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "InvalidCASignatureTest2EE", BAD_SIGNED_CA_CERT}, 
		                new String[] { BAD_SIGNED_CA_CRL, TRUST_ANCHOR_ROOT_CRL }, null);
	}

	@Test
	public void test4_1_3() throws Exception
	{
		nistTest(1, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "InvalidEESignatureTest3EE", GOOD_CA_CERT}, 
		                new String[] { GOOD_CA_CRL, TRUST_ANCHOR_ROOT_CRL }, null);
	}

	@Test
	public void test4_1_4() throws Exception
	{
		nistTest(0, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "ValidDSASignaturesTest4EE", DSA_CA_CERT}, 
		                new String[] { DSA_CA_CRL, TRUST_ANCHOR_ROOT_CRL }, null);
	}

	@Test
	public void test4_1_5() throws Exception
	{
		nistTest(0, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "ValidDSAParameterInheritanceTest5EE", DSA_PARAM_INHERITED_CA_CERT, DSA_CA_CERT}, 
		                new String[] { DSA_PARAM_INHERITED_CA_CRL, DSA_CA_CRL, TRUST_ANCHOR_ROOT_CRL }, null);
	}
	
	@Test
	public void test4_1_6() throws Exception
	{
		nistTest(1, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "InvalidDSASignatureTest6EE", DSA_CA_CERT}, 
		                new String[] { DSA_CA_CRL, TRUST_ANCHOR_ROOT_CRL }, null);
	}
	
	@Test
	public void test4_2_1() throws Exception
	{
		nistTest(1, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "InvalidCAnotBeforeDateTest1EE", "BadnotBeforeDateCACert"}, 
		                new String[] { "BadnotBeforeDateCACRL", TRUST_ANCHOR_ROOT_CRL }, null);
	}

	@Test
	public void test4_2_2() throws Exception
	{
		nistTest(1, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "InvalidEEnotBeforeDateTest2EE", GOOD_CA_CERT}, 
		                new String[] { GOOD_CA_CRL, TRUST_ANCHOR_ROOT_CRL }, null);
	}
	
	@Test
	public void test4_2_3() throws Exception
	{
		nistTest(0, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "Validpre2000UTCnotBeforeDateTest3EE", GOOD_CA_CERT}, 
		                new String[] { GOOD_CA_CRL, TRUST_ANCHOR_ROOT_CRL }, null);
	}
	
	@Test
	public void test4_2_4() throws Exception
	{
		nistTest(0, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "ValidGeneralizedTimenotBeforeDateTest4EE", GOOD_CA_CERT}, 
		                new String[] { GOOD_CA_CRL, TRUST_ANCHOR_ROOT_CRL }, null);
	}
	
	@Test
	public void test4_2_5() throws Exception
	{
		nistTest(1, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "InvalidCAnotAfterDateTest5EE", "BadnotAfterDateCACert"}, 
		                new String[] { "BadnotAfterDateCACRL", TRUST_ANCHOR_ROOT_CRL }, null);
	}
	
	@Test
	public void test4_2_6() throws Exception
	{
		nistTest(1, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "InvalidEEnotAfterDateTest6EE", GOOD_CA_CERT}, 
		                new String[] { GOOD_CA_CRL, TRUST_ANCHOR_ROOT_CRL }, null);
	}

	@Test
	public void test4_2_7() throws Exception
	{
		nistTest(2, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "Invalidpre2000UTCEEnotAfterDateTest7EE", GOOD_CA_CERT}, 
		                new String[] { GOOD_CA_CRL, TRUST_ANCHOR_ROOT_CRL }, null);
	}
	
	@Test
	public void test4_2_8() throws Exception
	{
		nistTest(0, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "ValidGeneralizedTimenotAfterDateTest8EE", GOOD_CA_CERT}, 
		                new String[] { GOOD_CA_CRL, TRUST_ANCHOR_ROOT_CRL }, null);
	}
	

	
	@Test
	public void test4_3_1() throws Exception
	{
		nistTest(2, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "InvalidNameChainingTest1EE", GOOD_CA_CERT}, 
		                new String[] { GOOD_CA_CRL, TRUST_ANCHOR_ROOT_CRL }, null);
	}
	@Test
	public void test4_3_2() throws Exception
	{
		nistTest(2, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "InvalidNameChainingOrderTest2EE", "NameOrderingCACert"}, 
		                new String[] { "NameOrderCACRL", TRUST_ANCHOR_ROOT_CRL }, null);
	}

	@Test
	public void test4_3_3() throws Exception
	{
		nistTest(0, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "ValidNameChainingWhitespaceTest3EE", GOOD_CA_CERT}, 
		                new String[] { GOOD_CA_CRL, TRUST_ANCHOR_ROOT_CRL }, null);
	}

	@Test
	public void test4_3_4() throws Exception
	{
		nistTest(0, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "ValidNameChainingWhitespaceTest4EE", GOOD_CA_CERT}, 
		                new String[] { GOOD_CA_CRL, TRUST_ANCHOR_ROOT_CRL }, null);
	}

	@Test
	public void test4_3_5() throws Exception
	{
		nistTest(0, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "ValidNameChainingCapitalizationTest5EE", GOOD_CA_CERT}, 
		                new String[] { GOOD_CA_CRL, TRUST_ANCHOR_ROOT_CRL }, null);
	}

	@Test
	public void test4_3_6() throws Exception
	{
		nistTest(0, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "ValidNameUIDsTest6EE",  "UIDCACert"}, 
		                new String[] { "UIDCACRL", TRUST_ANCHOR_ROOT_CRL }, null);
	}

	@Test
	public void test4_3_7() throws Exception
	{
		nistTest(0, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "ValidRFC3280MandatoryAttributeTypesTest7EE", "RFC3280MandatoryAttributeTypesCACert"}, 
		                new String[] { "RFC3280MandatoryAttributeTypesCACRL", TRUST_ANCHOR_ROOT_CRL }, null);
	}

	@Test
	public void test4_3_8() throws Exception
	{
		nistTest(0, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "ValidRFC3280OptionalAttributeTypesTest8EE", "RFC3280OptionalAttributeTypesCACert"}, 
		                new String[] { "RFC3280OptionalAttributeTypesCACRL", TRUST_ANCHOR_ROOT_CRL }, null);
	}

	@Test
	public void test4_3_9() throws Exception
	{
		nistTest(0, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "ValidUTF8StringEncodedNamesTest9EE", "UTF8StringEncodedNamesCACert"}, 
		                new String[] { "UTF8StringEncodedNamesCACRL", TRUST_ANCHOR_ROOT_CRL }, null);
	}

	@Test
	public void test4_3_10() throws Exception
	{
		nistTest(0, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "ValidRolloverfromPrintableStringtoUTF8StringTest10EE", "RolloverfromPrintableStringtoUTF8StringCACert"}, 
		                new String[] { "RolloverfromPrintableStringtoUTF8StringCACRL", TRUST_ANCHOR_ROOT_CRL }, null);
	}

	@Test
	public void test4_3_11() throws Exception
	{
		nistTest(0, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "ValidUTF8StringCaseInsensitiveMatchTest11EE", "UTF8StringCaseInsensitiveMatchCACert"}, 
		                new String[] { "UTF8StringCaseInsensitiveMatchCACRL", TRUST_ANCHOR_ROOT_CRL }, null);
	}

	
	@Test
	public void test4_4_1() throws Exception
	{
		nistTest(1, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "InvalidMissingCRLTest1EE", "NoCRLCACert"}, 
		                new String[] { TRUST_ANCHOR_ROOT_CRL }, null);
	}

	@Test
	public void test4_4_2() throws Exception
	{
		nistTest(1, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "InvalidRevokedCATest2EE", "RevokedsubCACert", GOOD_CA_CERT}, 
		                new String[] { "RevokedsubCACRL", GOOD_CA_CRL, TRUST_ANCHOR_ROOT_CRL }, null);
	}

	@Test
	public void test4_4_3() throws Exception
	{
		nistTest(1, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "InvalidRevokedEETest3EE", GOOD_CA_CERT}, 
		                new String[] { GOOD_CA_CRL, TRUST_ANCHOR_ROOT_CRL }, null);
	}

	@Test
	public void test4_4_4() throws Exception
	{
		nistTest(1, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "InvalidBadCRLSignatureTest4EE", "BadCRLSignatureCACert"}, 
		                new String[] { "BadCRLSignatureCACRL", TRUST_ANCHOR_ROOT_CRL }, null);
	}

	@Test
	public void test4_4_5() throws Exception
	{
		nistTest(1, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "InvalidBadCRLIssuerNameTest5EE", "BadCRLIssuerNameCACert"}, 
		                new String[] { "BadCRLIssuerNameCACRL", TRUST_ANCHOR_ROOT_CRL }, null);
	}

	@Test
	public void test4_4_6() throws Exception
	{
		nistTest(1, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "InvalidWrongCRLTest6EE", "WrongCRLCACert"}, 
		                new String[] { "WrongCRLCACRL", TRUST_ANCHOR_ROOT_CRL }, null);
	}

	@Test
	public void test4_4_7() throws Exception
	{
		nistTest(0, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "ValidTwoCRLsTest7EE", "TwoCRLsCACert"}, 
		                new String[] { "TwoCRLsCAGoodCRL", "TwoCRLsCABadCRL", TRUST_ANCHOR_ROOT_CRL }, null);
	}

	@Test
	public void test4_4_8() throws Exception
	{
		nistTest(1, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "InvalidUnknownCRLEntryExtensionTest8EE", "UnknownCRLEntryExtensionCACert"}, 
		                new String[] { "UnknownCRLEntryExtensionCACRL", TRUST_ANCHOR_ROOT_CRL }, null);
	}

	@Test
	public void test4_4_9() throws Exception
	{
		nistTest(1, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "InvalidUnknownCRLExtensionTest9EE", "UnknownCRLExtensionCACert"}, 
		                new String[] { "UnknownCRLExtensionCACRL", TRUST_ANCHOR_ROOT_CRL }, null);
	}

	@Test
	public void test4_4_10() throws Exception
	{
		nistTest(1, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "InvalidUnknownCRLExtensionTest10EE", "UnknownCRLExtensionCACert"}, 
		                new String[] { "UnknownCRLExtensionCACRL", TRUST_ANCHOR_ROOT_CRL }, null);
	}
	

	@Test
	public void test4_4_11() throws Exception
	{
		nistTest(1, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "InvalidOldCRLnextUpdateTest11EE", "OldCRLnextUpdateCACert"}, 
		                new String[] { "OldCRLnextUpdateCACRL", TRUST_ANCHOR_ROOT_CRL }, null);
	}

	@Test
	public void test4_4_12() throws Exception
	{
		nistTest(1, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "Invalidpre2000CRLnextUpdateTest12EE", "pre2000CRLnextUpdateCACert"}, 
		                new String[] { "pre2000CRLnextUpdateCACRL", TRUST_ANCHOR_ROOT_CRL }, null);
	}

	@Test
	public void test4_4_13() throws Exception
	{
		nistTest(0, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "ValidGeneralizedTimeCRLnextUpdateTest13EE", "GeneralizedTimeCRLnextUpdateCACert"}, 
		                new String[] { "GeneralizedTimeCRLnextUpdateCACRL", TRUST_ANCHOR_ROOT_CRL }, null);
	}

	@Test
	public void test4_4_14() throws Exception
	{
		nistTest(0, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "ValidNegativeSerialNumberTest14EE", "NegativeSerialNumberCACert"}, 
		                new String[] { "NegativeSerialNumberCACRL", TRUST_ANCHOR_ROOT_CRL }, null);
	}

	@Test
	public void test4_4_15() throws Exception
	{
		nistTest(1, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "InvalidNegativeSerialNumberTest15EE", "NegativeSerialNumberCACert"}, 
		                new String[] { "NegativeSerialNumberCACRL", TRUST_ANCHOR_ROOT_CRL }, null);
	}

	@Test
	public void test4_4_16() throws Exception
	{
		nistTest(0, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "ValidLongSerialNumberTest16EE", "LongSerialNumberCACert"}, 
		                new String[] { "LongSerialNumberCACRL", TRUST_ANCHOR_ROOT_CRL }, null);
	}

	@Test
	public void test4_4_17() throws Exception
	{
		nistTest(0, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "ValidLongSerialNumberTest17EE", "LongSerialNumberCACert"}, 
		                new String[] { "LongSerialNumberCACRL", TRUST_ANCHOR_ROOT_CRL }, null);
	}

	@Test
	public void test4_4_18() throws Exception
	{
		nistTest(1, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "InvalidLongSerialNumberTest18EE", "LongSerialNumberCACert"}, 
		                new String[] { "LongSerialNumberCACRL", TRUST_ANCHOR_ROOT_CRL }, null);
	}

	@Test
	public void test4_4_19() throws Exception
	{
		nistTest(0, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "ValidSeparateCertificateandCRLKeysTest19EE", 
				"SeparateCertificateandCRLKeysCRLSigningCert", 
				"SeparateCertificateandCRLKeysCertificateSigningCACert"}, 
		                new String[] { "SeparateCertificateandCRLKeysCRL", 
				TRUST_ANCHOR_ROOT_CRL }, null);
	}
	
	
	@Test
	public void test4_4_20() throws Exception
	{
		nistTest(1, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "InvalidSeparateCertificateandCRLKeysTest20EE", 
				"SeparateCertificateandCRLKeysCRLSigningCert", "SeparateCertificateandCRLKeysCertificateSigningCACert"}, 
		                new String[] { "SeparateCertificateandCRLKeysCRL", TRUST_ANCHOR_ROOT_CRL }, null);
	}

	@Test
	public void test4_4_21() throws Exception
	{
		nistTest(1, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "InvalidSeparateCertificateandCRLKeysTest21EE", 
				"SeparateCertificateandCRLKeysCA2CertificateSigningCACert",
				"SeparateCertificateandCRLKeysCA2CRLSigningCert"}, 
		                new String[] { "SeparateCertificateandCRLKeysCA2CRL", 
				TRUST_ANCHOR_ROOT_CRL }, null);
	}

	@Test
	public void test4_5_1() throws Exception
	{
		nistTest(0, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "ValidBasicSelfIssuedOldWithNewTest1EE", "BasicSelfIssuedNewKeyOldWithNewCACert", "BasicSelfIssuedNewKeyCACert"}, 
		                new String[] { "BasicSelfIssuedNewKeyCACRL", TRUST_ANCHOR_ROOT_CRL }, null);
	}
	
	@Test
	public void test4_5_2() throws Exception
	{
		nistTest(1, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "InvalidBasicSelfIssuedOldWithNewTest2EE", 
				"BasicSelfIssuedNewKeyOldWithNewCACert", "BasicSelfIssuedNewKeyCACert"}, 
		                new String[] { "BasicSelfIssuedNewKeyCACRL", TRUST_ANCHOR_ROOT_CRL }, null);
	}

	@Test
	public void test4_5_3() throws Exception
	{
		nistTest(0, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "ValidBasicSelfIssuedNewWithOldTest3EE", "BasicSelfIssuedOldKeyNewWithOldCACert", "BasicSelfIssuedOldKeyCACert"}, 
		                new String[] { "BasicSelfIssuedOldKeySelfIssuedCertCRL", "BasicSelfIssuedOldKeyCACRL", TRUST_ANCHOR_ROOT_CRL }, null);
	}

	@Test
	public void test4_5_4() throws Exception
	{
		nistTest(0, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "ValidBasicSelfIssuedNewWithOldTest4EE", "BasicSelfIssuedOldKeyNewWithOldCACert", "BasicSelfIssuedOldKeyCACert"}, 
		                new String[] { "BasicSelfIssuedOldKeyCACRL", "BasicSelfIssuedOldKeySelfIssuedCertCRL", TRUST_ANCHOR_ROOT_CRL }, null);
	}

	@Test
	public void test4_5_5() throws Exception
	{
		nistTest(1, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "InvalidBasicSelfIssuedNewWithOldTest5EE", "BasicSelfIssuedOldKeyNewWithOldCACert", "BasicSelfIssuedOldKeyCACert"}, 
		                new String[] { "BasicSelfIssuedOldKeyCACRL", "BasicSelfIssuedOldKeySelfIssuedCertCRL", TRUST_ANCHOR_ROOT_CRL }, null);
	}

	@Test
	public void test4_5_6() throws Exception
	{
		nistTest(0, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "ValidBasicSelfIssuedCRLSigningKeyTest6EE", "BasicSelfIssuedCRLSigningKeyCRLCert", "BasicSelfIssuedCRLSigningKeyCACert"}, 
		                new String[] { "BasicSelfIssuedCRLSigningKeyCRLCertCRL", "BasicSelfIssuedCRLSigningKeyCACRL", TRUST_ANCHOR_ROOT_CRL }, null);
	}

	@Test
	public void test4_5_7() throws Exception
	{
		nistTest(1, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "InvalidBasicSelfIssuedCRLSigningKeyTest7EE", "BasicSelfIssuedCRLSigningKeyCRLCert", "BasicSelfIssuedCRLSigningKeyCACert"}, 
		                new String[] { "BasicSelfIssuedCRLSigningKeyCRLCertCRL", "BasicSelfIssuedCRLSigningKeyCACRL", TRUST_ANCHOR_ROOT_CRL }, null);
	}

	@Test
	public void test4_5_8() throws Exception
	{
		nistTest(2, TRUST_ANCHOR_ROOT_CERTIFICATE, 
		                new String[] { "InvalidBasicSelfIssuedCRLSigningKeyTest8EE", "BasicSelfIssuedCRLSigningKeyCRLCert", "BasicSelfIssuedCRLSigningKeyCACert"}, 
		                new String[] { "BasicSelfIssuedCRLSigningKeyCRLCertCRL", "BasicSelfIssuedCRLSigningKeyCACRL", TRUST_ANCHOR_ROOT_CRL }, null);
	}
}
