/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509;

import eu.emi.security.authn.x509.impl.OpensslCertChainValidator;

/**
 * Used to define the CA namespace checking mode.
 * 
 * @author K. Benedyczak
 * @see OpensslCertChainValidator
 */
public enum NamespaceCheckingMode
{
	/**
	 * A Globus EACL is checked first. If found for the issuing CA then it is used and enforced.
	 * If not found then EuGridPMA namespaces definition is searched. If found for the issuing CA 
	 * then it is enforced.
	 * If no definition is present then namespaces check is considered to be passed.
	 */
	GLOBUS_EUGRIDPMA,
	
	/**
	 * An EuGridPMA namespaces definition is checked first. If found for the issuing CA then it is enforced.
	 * If not found then Globus EACL definition is searched. If found for the issuing CA 
	 * then it is enforced.
	 * If no definition is present then namespaces check is considered to be passed.
	 */
	EUGRIDPMA_GLOBUS, 
	
	/**
	 * A Globus EACL is checked only. If found for the issuing CA then it is used and enforced.
	 * If no definition is present then namespaces check is considered to be passed.
	 */
	GLOBUS,
	
	/**
	 * An EuGridPMA namespaces definition is checked only. If found for the issuing CA then it is enforced.
	 * If no definition is present then namespaces check is considered to be passed.
	 */
	EUGRIDPMA, 

	/**
	 * A Globus EACL is checked first. If found for the issuing CA then it is used and enforced.
	 * If not found then EuGridPMA namespaces definition is searched. If found for the issuing CA 
	 * then it is enforced.
	 * If no definition is present then namespaces check is considered to be failed.
	 */
	GLOBUS_EUGRIDPMA_REQUIRE,
	
	/**
	 * An EuGridPMA namespaces definition is checked first. If found for the issuing CA then it is enforced.
	 * If not found then Globus EACL definition is searched. If found for the issuing CA 
	 * then it is enforced.
	 * If no definition is present then namespaces check is considered to be failed.
	 */
	EUGRIDPMA_GLOBUS_REQUIRE, 
	
	/**
	 * A Globus EACL is checked only. If found for the issuing CA then it is used and enforced.
	 * If no definition is present then namespaces check is considered to be failed.
	 */
	GLOBUS_REQUIRE,
	
	/**
	 * An EuGridPMA namespaces definition is checked only. If found for the issuing CA then it is enforced.
	 * If no definition is present then namespaces check is considered to be failed.
	 */
	EUGRIDPMA_REQUIRE, 

	/**
	 * Both EuGridPMA namespaces definition and Globus EACL are enforced for the issuer.
	 * If no definition is present then namespaces check is considered to be passed.
	 */
	EUGRIDPMA_AND_GLOBUS,
	
	/**
	 * Both EuGridPMA namespaces definition and Globus EACL are enforced for the issuer.
	 * If no definition is present then namespaces check is considered to be failed.
	 */
	EUGRIDPMA_AND_GLOBUS_REQUIRE, 
	
	/**
	 * CA namespaces are fully ignored, even if present. 
	 */
	IGNORE;
	
	public boolean globusEnabled()
	{
		return !(this == IGNORE || this == EUGRIDPMA || this == EUGRIDPMA_REQUIRE);
	}
	
	public boolean euGridPmaEnabled()
	{
		return !(this == IGNORE || this == GLOBUS || this == GLOBUS_REQUIRE);
	}
	
	public boolean isRequired()
	{
		return this == GLOBUS_REQUIRE || this == EUGRIDPMA_REQUIRE || this == EUGRIDPMA_GLOBUS_REQUIRE ||
				this == GLOBUS_EUGRIDPMA_REQUIRE || this == EUGRIDPMA_AND_GLOBUS_REQUIRE;
	}

	public boolean isGlobusFirst()
	{
		return this == GLOBUS_REQUIRE || this == GLOBUS_EUGRIDPMA_REQUIRE || 
				this == GLOBUS || this == GLOBUS_EUGRIDPMA;
	}
}
