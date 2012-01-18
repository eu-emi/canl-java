/*
 * Copyright (c) 2011 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.impl;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

/**
 * This file includes tests from sections 4.13 to 4.16
 * 
 * @see http://csrc.nist.gov/groups/ST/crypto_apps_infra/pki/pkitesting.html
 * @author K. Benedyczak
 */
public class NISTValidator13_16Test extends NISTValidatorTestBase
{
	private void convertToNist(int e, String[] a, String[] b)
			throws Exception
	{
		List<String> crls = new ArrayList<String>();
		for (int i=1; i<a.length; i++)
			crls.add(a[i]);
		crls.add(TRUST_ANCHOR_ROOT_CRL);

		nistTest(e, TRUST_ANCHOR_ROOT_CERTIFICATE, new String[] { b[0],
				a[0] }, crls.toArray(new String[0]), null);
	}

	private void convertToNist(int e, String[] a, String[] b, String[] c)
			throws Exception
	{
		List<String> crls = new ArrayList<String>();
		for (int i=1; i<b.length; i++)
			crls.add(b[i]);
		for (int i=1; i<a.length; i++)
			crls.add(a[i]);
		crls.add(TRUST_ANCHOR_ROOT_CRL);
		nistTest(e, TRUST_ANCHOR_ROOT_CERTIFICATE, new String[] { c[0],
				b[0], a[0] }, crls.toArray(new String[0]), null);
	}

	@Test
	public void test4_13_1() throws Exception
	{
		convertToNist(0,
				new String[] { "nameConstraintsDN1CACert",
						"nameConstraintsDN1CACRL" },
				new String[] { "ValidDNnameConstraintsTest1EE" });
	}

	@Test
	public void test4_13_2() throws Exception
	{
		convertToNist(1,
				new String[] { "nameConstraintsDN1CACert",
						"nameConstraintsDN1CACRL" },
				new String[] { "InvalidDNnameConstraintsTest2EE" });
	}

	@Test
	public void test4_13_3() throws Exception
	{
		convertToNist(1,
				new String[] { "nameConstraintsDN1CACert",
						"nameConstraintsDN1CACRL" },
				new String[] { "InvalidDNnameConstraintsTest3EE" });
	}

	@Test
	public void test4_13_4() throws Exception
	{
		convertToNist(0,
				new String[] { "nameConstraintsDN1CACert",
						"nameConstraintsDN1CACRL" },
				new String[] { "ValidDNnameConstraintsTest4EE" });
	}

	@Test
	public void test4_13_5() throws Exception
	{
		convertToNist(0,
				new String[] { "nameConstraintsDN2CACert",
						"nameConstraintsDN2CACRL" },
				new String[] { "ValidDNnameConstraintsTest5EE" });
	}

	@Test
	public void test4_13_6() throws Exception
	{
		convertToNist(0,
				new String[] { "nameConstraintsDN3CACert",
						"nameConstraintsDN3CACRL" },
				new String[] { "ValidDNnameConstraintsTest6EE" });
	}

	@Test
	public void test4_13_7() throws Exception
	{
		convertToNist(1,
				new String[] { "nameConstraintsDN3CACert",
						"nameConstraintsDN3CACRL" },
				new String[] { "InvalidDNnameConstraintsTest7EE" });
	}

	@Test
	public void test4_13_8() throws Exception
	{
		convertToNist(1,
				new String[] { "nameConstraintsDN4CACert",
						"nameConstraintsDN4CACRL" },
				new String[] { "InvalidDNnameConstraintsTest8EE" });
	}

	@Test
	public void test4_13_9() throws Exception
	{
		convertToNist(1,
				new String[] { "nameConstraintsDN4CACert",
						"nameConstraintsDN4CACRL" },
				new String[] { "InvalidDNnameConstraintsTest9EE" });
	}

	@Test
	public void test4_13_10() throws Exception
	{
		convertToNist(1,
				new String[] { "nameConstraintsDN5CACert",
						"nameConstraintsDN5CACRL" },
				new String[] { "InvalidDNnameConstraintsTest10EE" });
	}

	@Test
	public void test4_13_11() throws Exception
	{
		convertToNist(0,
				new String[] { "nameConstraintsDN5CACert",
						"nameConstraintsDN5CACRL" },
				new String[] { "ValidDNnameConstraintsTest11EE" });
	}

	@Test
	public void test4_13_12() throws Exception
	{
		convertToNist(1,
				new String[] { "nameConstraintsDN1CACert",
						"nameConstraintsDN1CACRL" },
				new String[] { "nameConstraintsDN1subCA1Cert",
						"nameConstraintsDN1subCA1CRL" },
				new String[] { "InvalidDNnameConstraintsTest12EE" });
	}

	@Test
	public void test4_13_13() throws Exception
	{
		convertToNist(1,
				new String[] { "nameConstraintsDN1CACert",
						"nameConstraintsDN1CACRL" },
				new String[] { "nameConstraintsDN1subCA2Cert",
						"nameConstraintsDN1subCA2CRL" },
				new String[] { "InvalidDNnameConstraintsTest13EE" });
	}

	@Test
	public void test4_13_14() throws Exception
	{
		convertToNist(0,
				new String[] { "nameConstraintsDN1CACert",
						"nameConstraintsDN1CACRL" },
				new String[] { "nameConstraintsDN1subCA2Cert",
						"nameConstraintsDN1subCA2CRL" },
				new String[] { "ValidDNnameConstraintsTest14EE" });
	}

	@Test
	public void test4_13_15() throws Exception
	{
		convertToNist(1,
				new String[] { "nameConstraintsDN3CACert",
						"nameConstraintsDN3CACRL" },
				new String[] { "nameConstraintsDN3subCA1Cert",
						"nameConstraintsDN3subCA1CRL" },
				new String[] { "InvalidDNnameConstraintsTest15EE" });
	}

	@Test
	public void test4_13_16() throws Exception
	{
		convertToNist(1,
				new String[] { "nameConstraintsDN3CACert",
						"nameConstraintsDN3CACRL" },
				new String[] { "nameConstraintsDN3subCA1Cert",
						"nameConstraintsDN3subCA1CRL" },
				new String[] { "InvalidDNnameConstraintsTest16EE" });
	}

	@Test
	public void test4_13_17() throws Exception
	{
		convertToNist(1,
				new String[] { "nameConstraintsDN3CACert",
						"nameConstraintsDN3CACRL" },
				new String[] { "nameConstraintsDN3subCA2Cert",
						"nameConstraintsDN3subCA2CRL" },
				new String[] { "InvalidDNnameConstraintsTest17EE" });
	}

	@Test
	public void test4_13_18() throws Exception
	{
		convertToNist(0,
				new String[] { "nameConstraintsDN3CACert",
						"nameConstraintsDN3CACRL" },
				new String[] { "nameConstraintsDN3subCA2Cert",
						"nameConstraintsDN3subCA2CRL" },
				new String[] { "ValidDNnameConstraintsTest18EE" });
	}
/* FIXME - problem with signature validation
	@Test
	public void test4_13_19() throws Exception
	{
		convertToNist(0,
				new String[] { "nameConstraintsDN1CACert",
						"nameConstraintsDN1CACRL" },
				new String[] { "nameConstraintsDN1SelfIssuedCACert" },
				new String[] { "ValidDNnameConstraintsTest19EE" });
	}
*/
	@Test
	public void test4_13_20() throws Exception
	{
		convertToNist(2,
				new String[] { "nameConstraintsDN1CACert",
						"nameConstraintsDN1CACRL" },
				new String[] { "InvalidDNnameConstraintsTest20EE" });
	}

	@Test
	public void test4_13_21() throws Exception
	{
		convertToNist(0,
				new String[] { "nameConstraintsRFC822CA1Cert",
						"nameConstraintsRFC822CA1CRL" },
				new String[] { "ValidRFC822nameConstraintsTest21EE" });
	}

	@Test
	public void test4_13_22() throws Exception
	{
		convertToNist(1,
				new String[] { "nameConstraintsRFC822CA1Cert",
						"nameConstraintsRFC822CA1CRL" },
				new String[] { "InvalidRFC822nameConstraintsTest22EE" });
	}

	@Test
	public void test4_13_23() throws Exception
	{
		convertToNist(0,
				new String[] { "nameConstraintsRFC822CA2Cert",
						"nameConstraintsRFC822CA2CRL" },
				new String[] { "ValidRFC822nameConstraintsTest23EE" });
	}

	@Test
	public void test4_13_24() throws Exception
	{
		convertToNist(1,
				new String[] { "nameConstraintsRFC822CA2Cert",
						"nameConstraintsRFC822CA2CRL" },
				new String[] { "InvalidRFC822nameConstraintsTest24EE" });
	}

	@Test
	public void test4_13_25() throws Exception
	{
		convertToNist(0,
				new String[] { "nameConstraintsRFC822CA3Cert",
						"nameConstraintsRFC822CA3CRL" },
				new String[] { "ValidRFC822nameConstraintsTest25EE" });
	}

	@Test
	public void test4_13_26() throws Exception
	{
		convertToNist(1,
				new String[] { "nameConstraintsRFC822CA3Cert",
						"nameConstraintsRFC822CA3CRL" },
				new String[] { "InvalidRFC822nameConstraintsTest26EE" });
	}

	@Test
	public void test4_13_27() throws Exception
	{
		convertToNist(0,
				new String[] { "nameConstraintsDN1CACert",
						"nameConstraintsDN1CACRL" },
				new String[] { "nameConstraintsDN1subCA3Cert",
						"nameConstraintsDN1subCA3CRL" },
				new String[] { "ValidDNandRFC822nameConstraintsTest27EE" });
	}

	@Test
	public void test4_13_28() throws Exception
	{
		convertToNist(1,
				new String[] { "nameConstraintsDN1CACert",
						"nameConstraintsDN1CACRL" },
				new String[] { "nameConstraintsDN1subCA3Cert",
						"nameConstraintsDN1subCA3CRL" },
				new String[] { "InvalidDNandRFC822nameConstraintsTest28EE" });
	}

	@Test
	public void test4_13_29() throws Exception
	{
		convertToNist(1,
				new String[] { "nameConstraintsDN1CACert",
						"nameConstraintsDN1CACRL" },
				new String[] { "nameConstraintsDN1subCA3Cert",
						"nameConstraintsDN1subCA3CRL" },
				new String[] { "InvalidDNandRFC822nameConstraintsTest29EE" });
	}

	@Test
	public void test4_13_30() throws Exception
	{
		convertToNist(0,
				new String[] { "nameConstraintsDNS1CACert",
						"nameConstraintsDNS1CACRL" },
				new String[] { "ValidDNSnameConstraintsTest30EE" });
	}

	@Test
	public void test4_13_31() throws Exception
	{
		convertToNist(1,
				new String[] { "nameConstraintsDNS1CACert",
						"nameConstraintsDNS1CACRL" },
				new String[] { "InvalidDNSnameConstraintsTest31EE" });
	}

	@Test
	public void test4_13_32() throws Exception
	{
		convertToNist(0,
				new String[] { "nameConstraintsDNS2CACert",
						"nameConstraintsDNS2CACRL" },
				new String[] { "ValidDNSnameConstraintsTest32EE" });
	}

	@Test
	public void test4_13_33() throws Exception
	{
		convertToNist(1,
				new String[] { "nameConstraintsDNS2CACert",
						"nameConstraintsDNS2CACRL" },
				new String[] { "InvalidDNSnameConstraintsTest33EE" });
	}

	@Test
	public void test4_13_34() throws Exception
	{
		convertToNist(0,
				new String[] { "nameConstraintsURI1CACert",
						"nameConstraintsURI1CACRL" },
				new String[] { "ValidURInameConstraintsTest34EE" });
	}

	@Test
	public void test4_13_35() throws Exception
	{
		convertToNist(1,
				new String[] { "nameConstraintsURI1CACert",
						"nameConstraintsURI1CACRL" },
				new String[] { "InvalidURInameConstraintsTest35EE" });
	}

	@Test
	public void test4_13_36() throws Exception
	{
		convertToNist(0,
				new String[] { "nameConstraintsURI2CACert",
						"nameConstraintsURI2CACRL" },
				new String[] { "ValidURInameConstraintsTest36EE" });
	}

	@Test
	public void test4_13_37() throws Exception
	{
		convertToNist(1,
				new String[] { "nameConstraintsURI2CACert",
						"nameConstraintsURI2CACRL" },
				new String[] { "InvalidURInameConstraintsTest37EE" });
	}

	@Test
	public void test4_13_38() throws Exception
	{
		convertToNist(1,
				new String[] { "nameConstraintsDNS1CACert",
						"nameConstraintsDNS1CACRL" },
				new String[] { "InvalidDNSnameConstraintsTest38EE" });
	}
	
	
	
	
	@Test
	public void test4_14_1() throws Exception
	{
		convertToNist(0,
				new String[] { "distributionPoint1CACert",
						"distributionPoint1CACRL" },
				new String[] { "ValiddistributionPointTest1EE" });
	}

	@Test
	public void test4_14_2() throws Exception
	{
		convertToNist(1,
				new String[] { "distributionPoint1CACert",
						"distributionPoint1CACRL" },
				new String[] { "InvaliddistributionPointTest2EE" });
	}

	@Test
	public void test4_14_3() throws Exception
	{
		convertToNist(1,
				new String[] { "distributionPoint1CACert",
						"distributionPoint1CACRL" },
				new String[] { "InvaliddistributionPointTest3EE" });
	}

	@Test
	public void test4_14_4() throws Exception
	{
		convertToNist(0,
				new String[] { "distributionPoint1CACert",
						"distributionPoint1CACRL" },
				new String[] { "ValiddistributionPointTest4EE" });
	}

	@Test
	public void test4_14_5() throws Exception
	{
		convertToNist(0,
				new String[] { "distributionPoint2CACert",
						"distributionPoint2CACRL" },
				new String[] { "ValiddistributionPointTest5EE" });
	}

	@Test
	public void test4_14_6() throws Exception
	{
		convertToNist(1,
				new String[] { "distributionPoint2CACert",
						"distributionPoint2CACRL" },
				new String[] { "InvaliddistributionPointTest6EE" });
	}

	@Test
	public void test4_14_7() throws Exception
	{
		convertToNist(0,
				new String[] { "distributionPoint2CACert",
						"distributionPoint2CACRL" },
				new String[] { "ValiddistributionPointTest7EE" });
	}

	@Test
	public void test4_14_8() throws Exception
	{
		convertToNist(1,
				new String[] { "distributionPoint2CACert",
						"distributionPoint2CACRL" },
				new String[] { "InvaliddistributionPointTest8EE" });
	}

	@Test
	public void test4_14_9() throws Exception
	{
		convertToNist(1,
				new String[] { "distributionPoint2CACert",
						"distributionPoint2CACRL" },
				new String[] { "InvaliddistributionPointTest9EE" });
	}

	@Test
	public void test4_14_10() throws Exception
	{
		convertToNist(0,
				new String[] {
						"NoissuingDistributionPointCACert",
						"NoissuingDistributionPointCACRL" },
				new String[] { "ValidNoissuingDistributionPointTest10EE" });
	}

	@Test
	public void test4_14_11() throws Exception
	{
		convertToNist(1,
				new String[] { "onlyContainsUserCertsCACert",
						"onlyContainsUserCertsCACRL" },
				new String[] { "InvalidonlyContainsUserCertsTest11EE" });
	}

	@Test
	public void test4_14_12() throws Exception
	{
		convertToNist(1,
				new String[] { "onlyContainsCACertsCACert",
						"onlyContainsCACertsCACRL" },
				new String[] { "InvalidonlyContainsCACertsTest12EE" });
	}

	@Test
	public void test4_14_13() throws Exception
	{
		convertToNist(0,
				new String[] { "onlyContainsCACertsCACert",
						"onlyContainsCACertsCACRL" },
				new String[] { "ValidonlyContainsCACertsTest13EE" });
	}

	@Test
	public void test4_14_14() throws Exception
	{
		convertToNist(1,
				new String[] {
						"onlyContainsAttributeCertsCACert",
						"onlyContainsAttributeCertsCACRL" },
				new String[] { "InvalidonlyContainsAttributeCertsTest14EE" });
	}

	@Test
	public void test4_14_15() throws Exception
	{
		convertToNist(1,
				new String[] {
						"onlySomeReasonsCA1Cert",
						"onlySomeReasonsCA1compromiseCRL",
						"onlySomeReasonsCA1otherreasonsCRL" },
				new String[] { "InvalidonlySomeReasonsTest15EE" });
	}

	@Test
	public void test4_14_16() throws Exception
	{
		convertToNist(1,
				new String[] {
						"onlySomeReasonsCA1Cert",
						"onlySomeReasonsCA1compromiseCRL",
						"onlySomeReasonsCA1otherreasonsCRL" },
				new String[] { "InvalidonlySomeReasonsTest16EE" });
	}

	@Test
	public void test4_14_17() throws Exception
	{
		convertToNist(1,
				new String[] { "onlySomeReasonsCA2Cert",
						"onlySomeReasonsCA2CRL1",
						"onlySomeReasonsCA2CRL2" },
				new String[] { "InvalidonlySomeReasonsTest17EE" });
	}

	@Test
	public void test4_14_18() throws Exception
	{
		convertToNist(0, new String[] { "onlySomeReasonsCA3Cert",
				"onlySomeReasonsCA3compromiseCRL", 
				"onlySomeReasonsCA3otherreasonsCRL" },
				new String[] { "ValidonlySomeReasonsTest18EE" });
	}

	@Test
	public void test4_14_19() throws Exception
	{
		convertToNist(0, new String[] { "onlySomeReasonsCA4Cert",
				"onlySomeReasonsCA4compromiseCRL",
				"onlySomeReasonsCA4otherreasonsCRL" },
				new String[] { "ValidonlySomeReasonsTest19EE" });
	}

	@Test
	public void test4_14_20() throws Exception
	{
		convertToNist(1,
				new String[] {
						"onlySomeReasonsCA4Cert",
						"onlySomeReasonsCA4compromiseCRL",
						"onlySomeReasonsCA4otherreasonsCRL" },
				new String[] { "InvalidonlySomeReasonsTest20EE" });
	}

	@Test
	public void test4_14_21() throws Exception
	{
		convertToNist(1,
				new String[] {
						"onlySomeReasonsCA4Cert",
						"onlySomeReasonsCA4compromiseCRL",
						"onlySomeReasonsCA4otherreasonsCRL" },
				new String[] { "InvalidonlySomeReasonsTest21EE" });
	}

	@Test
	public void test4_14_22() throws Exception
	{
		convertToNist(0,
				new String[] { "indirectCRLCA1Cert",
						"indirectCRLCA1CRL" },
				new String[] { "ValidIDPwithindirectCRLTest22EE" });
	}

	@Test
	public void test4_14_23() throws Exception
	{
		convertToNist(1,
				new String[] { "indirectCRLCA1Cert",
						"indirectCRLCA1CRL" },
				new String[] { "InvalidIDPwithindirectCRLTest23EE" });
	}

	@Test
	public void test4_14_24() throws Exception
	{
		convertToNist(0,
				new String[] { "indirectCRLCA2Cert" },
				new String[] { "indirectCRLCA1Cert",
						"indirectCRLCA1CRL" },
				new String[] { "ValidIDPwithindirectCRLTest24EE" });
	}

	@Test
	public void test4_14_25() throws Exception
	{
		convertToNist(0,
				new String[] { "indirectCRLCA2Cert" },
				new String[] { "indirectCRLCA1Cert",
						"indirectCRLCA1CRL" },
				new String[] { "ValidIDPwithindirectCRLTest25EE" });
	}

	@Test
	public void test4_14_26() throws Exception
	{
		convertToNist(1,
				new String[] { "indirectCRLCA2Cert" },
				new String[] { "indirectCRLCA1Cert",
						"indirectCRLCA1CRL" },
				new String[] { "InvalidIDPwithindirectCRLTest26EE" });
	}

	@Test
	public void test4_14_27() throws Exception
	{
		convertToNist(1, new String[] { "indirectCRLCA2Cert" },
				new String[] { "GoodCACert", "GoodCACRL" },
				new String[] { "InvalidcRLIssuerTest27EE" });
	}

	@Test
	public void test4_14_28() throws Exception
	{
		convertToNist(0, new String[] { "indirectCRLCA3Cert",
				"indirectCRLCA3CRL" }, new String[] {
				"indirectCRLCA3cRLIssuerCert",
				"indirectCRLCA3cRLIssuerCRL" },
				new String[] { "ValidcRLIssuerTest28EE" });
	}

	@Test
	public void test4_14_29() throws Exception
	{
		convertToNist(0, new String[] { "indirectCRLCA3Cert",
				"indirectCRLCA3CRL" }, new String[] {
				"indirectCRLCA3cRLIssuerCert",
				"indirectCRLCA3cRLIssuerCRL" },
				new String[] { "ValidcRLIssuerTest29EE" });
	}

	@Test
	public void test4_14_30() throws Exception
	{
		convertToNist(0, new String[] { "indirectCRLCA4Cert" }, new String[] {
				"indirectCRLCA4cRLIssuerCert",
				"indirectCRLCA4cRLIssuerCRL" },
				new String[] { "ValidcRLIssuerTest30EE" });
	}

	@Test
	public void test4_14_31() throws Exception
	{
		convertToNist(1, new String[] { "indirectCRLCA5Cert",
				"indirectCRLCA5CRL" },
				new String[] { "indirectCRLCA6Cert" },
				new String[] { "InvalidcRLIssuerTest31EE" });
	}

	@Test
	public void test4_14_32() throws Exception
	{
		convertToNist(1, new String[] { "indirectCRLCA5Cert",
				"indirectCRLCA5CRL" },
				new String[] { "indirectCRLCA6Cert" },
				new String[] { "InvalidcRLIssuerTest32EE" });
	}

	@Test
	public void test4_14_33() throws Exception
	{
		convertToNist(0, new String[] { "indirectCRLCA5Cert",
				"indirectCRLCA5CRL" },
				new String[] { "indirectCRLCA6Cert" },
				new String[] { "ValidcRLIssuerTest33EE" });
	}

	@Test
	public void test4_14_34() throws Exception
	{
		convertToNist(1, new String[] { "indirectCRLCA5Cert",
				"indirectCRLCA5CRL" },
				new String[] { "InvalidcRLIssuerTest34EE" });
	}

	@Test
	public void test4_14_35() throws Exception
	{
		convertToNist(1, new String[] { "indirectCRLCA5Cert",
				"indirectCRLCA5CRL" },
				new String[] { "InvalidcRLIssuerTest35EE" });
	}
	
	
	
	@Test
	public void test4_15_1() throws Exception
	{
		convertToNist(1,				
				new String[] { "deltaCRLIndicatorNoBaseCACert", "deltaCRLIndicatorNoBaseCACRL"},
				new String[] { "InvaliddeltaCRLIndicatorNoBaseTest1EE"});
	}
	
	@Test
	public void test4_15_2() throws Exception
	{
		convertToNist(0,				
				new String[] { "deltaCRLCA1Cert", "deltaCRLCA1CRL", "deltaCRLCA1deltaCRL"},
				new String[] { "ValiddeltaCRLTest2EE"});
	}
	
	@Test
	public void test4_15_3() throws Exception
	{
		convertToNist(1,				
				new String[] { "deltaCRLCA1Cert", "deltaCRLCA1CRL", "deltaCRLCA1deltaCRL"},
				new String[] { "InvaliddeltaCRLTest3EE"});
	}
	
	@Test
	public void test4_15_4() throws Exception
	{
		convertToNist(1,				
				new String[] { "deltaCRLCA1Cert", "deltaCRLCA1CRL", "deltaCRLCA1deltaCRL"},
				new String[] { "InvaliddeltaCRLTest4EE"});
	}
	
	@Test
	public void test4_15_5() throws Exception
	{
		convertToNist(0,				
				new String[] { "deltaCRLCA1Cert", "deltaCRLCA1CRL", "deltaCRLCA1deltaCRL"},
				new String[] { "ValiddeltaCRLTest5EE"});
	}
	
	@Test
	public void test4_15_6() throws Exception
	{
		convertToNist(1,				
				new String[] { "deltaCRLCA1Cert", "deltaCRLCA1CRL", "deltaCRLCA1deltaCRL"},
				new String[] { "InvaliddeltaCRLTest6EE"});
	}
	
	@Test
	public void test4_15_7() throws Exception
	{
		convertToNist(0,				
				new String[] { "deltaCRLCA1Cert", "deltaCRLCA1CRL", "deltaCRLCA1deltaCRL"},
				new String[] { "ValiddeltaCRLTest7EE"});
	}
	
	@Test
	public void test4_15_8() throws Exception
	{
		convertToNist(0,				
				new String[] { "deltaCRLCA2Cert", "deltaCRLCA2CRL", "deltaCRLCA2deltaCRL"},
				new String[] { "ValiddeltaCRLTest8EE"});
	}
	
	@Test
	public void test4_15_9() throws Exception
	{
		convertToNist(1,				
				new String[] { "deltaCRLCA2Cert", "deltaCRLCA2CRL", "deltaCRLCA2deltaCRL"},
				new String[] { "InvaliddeltaCRLTest9EE"});
	}
	
	@Test
	public void test4_15_10() throws Exception
	{
		convertToNist(1,				
				new String[] { "deltaCRLCA3Cert", "deltaCRLCA3CRL", "deltaCRLCA3deltaCRL"},
				new String[] { "InvaliddeltaCRLTest10EE"});
	}
	
	@Test
	public void test4_16_1() throws Exception
	{
		nistTest(0, TRUST_ANCHOR_ROOT_CERTIFICATE, 
				new String[] { "ValidUnknownNotCriticalCertificateExtensionTest1EE" }, 
				new String[] { TRUST_ANCHOR_ROOT_CRL }, null);
	}
	
	@Test
	public void test4_16_2() throws Exception
	{
		nistTest(1, TRUST_ANCHOR_ROOT_CERTIFICATE, 
				new String[] { "InvalidUnknownCriticalCertificateExtensionTest2EE" }, 
				new String[] { TRUST_ANCHOR_ROOT_CRL }, null);
	}
	
}
