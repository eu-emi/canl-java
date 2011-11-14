/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.impl;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static eu.emi.security.authn.x509.impl.FormatMode.*;


/**
 * Utility allowing for converting certificates to various text representations.
 * 
 * @author K. Benedyczak
 */
public class X509Formatter
{
	private final FormatMode mode;
	private static final String[] USAGES = {
		"digitalSignature",
		"nonRepudiation",
		"keyEncipherment",
		"dataEncipherment",
		"keyAgreement",
		"keyCertSign",
		"CRLSign",
		"encipherOnly",
		"decipherOnly"};
	
	private static final String EKU = "1.3.6.1.5.5.7.3.";
	private static final Map<String, String> EXT_USAGES = new HashMap<String, String>(16);

	static {
		EXT_USAGES.put("2.5.29.37.0", "anyExtendedKeyUsage");
		EXT_USAGES.put(EKU+"1", "serverAuth");
		EXT_USAGES.put(EKU+"2", "clientAuth");
		EXT_USAGES.put(EKU+"3", "codeSigning");
		EXT_USAGES.put(EKU+"4", "emailProtection");
		EXT_USAGES.put(EKU+"5", "ipsecEndSystem");
		EXT_USAGES.put(EKU+"6", "ipsecTunnel");
		EXT_USAGES.put(EKU+"7", "ipsecUser");
		EXT_USAGES.put(EKU+"8", "timeStamping");
		EXT_USAGES.put(EKU+"9", "OCSPSigning");
		EXT_USAGES.put(EKU+"10", "dvcs");
		EXT_USAGES.put(EKU+"11", "sbgpCertAAServerAuth");
		EXT_USAGES.put(EKU+"12", "scvp_responder");
		EXT_USAGES.put(EKU+"13", "eapOverPPP");
		EXT_USAGES.put(EKU+"14", "eapOverLAN");
		EXT_USAGES.put(EKU+"15", "scvpServer");
		EXT_USAGES.put(EKU+"16", "scvpClient");
		EXT_USAGES.put(EKU+"17", "ipsecIKE");
		EXT_USAGES.put(EKU+"18", "capwapAC");
		EXT_USAGES.put(EKU+"19", "capwapWTP");
		EXT_USAGES.put("1.3.6.1.4.1.311.20.2.2", "smartcardlogon");
	};
	
	/**
	 * Creates a new X509Formatter object
	 * @param mode the formatting mode that will be used by this object.
	 */
	public X509Formatter(FormatMode mode)
	{
		this.mode = mode;
	}
	
	/**
	 * Produces a human readable text representation of the provided certificate. 
	 * @param cert input certificate
	 * @return the text representation
	 */
	public String format(X509Certificate cert)
	{
		String sep = "\n";
		if (mode.equals(COMPACT_ONE_LINE) || mode.equals(MEDIUM_ONE_LINE))
			sep = ", ";
		
		StringBuilder sb = new StringBuilder(256);
		String subject = X500NameUtils.getReadableForm(
				cert.getSubjectX500Principal());
		String issuer = X500NameUtils.getReadableForm(
				cert.getIssuerX500Principal());
		int version = cert.getVersion();
		sb.append(cert.getType()).append(" v").append(version);
		sb.append(" certificate").append(sep);
		sb.append("Subject: ").append(subject).append(sep);
		sb.append("Issuer: ").append(issuer);
		if (mode.equals(COMPACT) || mode.equals(COMPACT_ONE_LINE))
			return sb.toString();
		
		sb.append(sep);
		sb.append("Valid from: " + cert.getNotBefore()).append(sep);
		sb.append("Valid to: " + cert.getNotAfter());
		
		if (mode.equals(MEDIUM) || mode.equals(MEDIUM_ONE_LINE))
			return sb.toString();
		
		sb.append(sep);
		
		Collection<List<?>> issuerAltNames;
		Collection<List<?>> subjAltNames;
		List<String> extKeyUsage;
		try
		{
			issuerAltNames = cert.getIssuerAlternativeNames();
			subjAltNames = cert.getSubjectAlternativeNames();
			extKeyUsage = cert.getExtendedKeyUsage();
		} catch (CertificateParsingException e)
		{
			throw new IllegalArgumentException(
					"The certificate can not be sucessfuly parsed", e);
		}
		if (issuerAltNames != null)
			appendAltNames(sb, "Issuer alternative names", sep, issuerAltNames);
		if (subjAltNames != null)
			appendAltNames(sb, "Subject alternative names", sep, subjAltNames);

		boolean isCA = cert.getBasicConstraints() == Integer.MAX_VALUE;
		sb.append("CA: ").append(isCA).append(sep);

		
		
		PublicKey pubKey = cert.getPublicKey();

		String bits = "";
		if (pubKey instanceof RSAPublicKey)
			bits = " " + ((RSAPublicKey)pubKey).getModulus().bitLength() + "bit";
		if (pubKey instanceof DSAPublicKey)
			bits = " " + ((DSAPublicKey)pubKey).getParams().getG().bitLength() + "bit";
		
		String sigAlg = cert.getSigAlgName();
		sb.append("Signature alg: ").append(sigAlg).append(sep);
		sb.append("Public key type: ").append(pubKey.getAlgorithm()).append(bits).append(sep);
		
		
		boolean []keyUsage = cert.getKeyUsage();
		if (keyUsage != null)
		{
			sb.append("Allowed usage:");
			for (int i=0; i<keyUsage.length; i++)
				if (keyUsage[i])
					sb.append(" ").append(USAGES[i]);
			sb.append(sep);
		}
		if (extKeyUsage != null)
		{
			sb.append("Allowed extended usage:");
			for (String oid: extKeyUsage)
			{
				String val = EXT_USAGES.get(oid);
				if (val == null)
					val = oid;
				sb.append(" ").append(val);
			}
			sb.append(sep);
		}
		BigInteger serial = cert.getSerialNumber();
		sb.append("Serial number: ").append(serial);
		return sb.toString();
	}

	private void appendAltNames(StringBuilder sb, String info, String sep, 
			Collection<List<?>> altNames)
	{
		sb.append(info).append(": ").append(sep);
		for (List<?> altNamesL: altNames)
		{
			sb.append("  ");
			Integer i = (Integer) altNamesL.get(0);
			Object rVal = altNamesL.get(1);
			String val;
			if (i == 0 || i == 3 || i == 5)
				val = Arrays.toString((byte[])rVal);
			else
				val = (String) rVal;
			switch (i)
			{
			case 1:
				sb.append("email: ").append(val).append(sep);
				break;
			case 2:
				sb.append("DNS: ").append(val).append(sep);
				break;
			case 4:
				sb.append("DN: ").append(val).append(sep);
				break;
			case 6:
				sb.append("URI: ").append(val).append(sep);
				break;
			case 7:
				sb.append("IP: ").append(val).append(sep);
				break;
			case 8:
				sb.append("OID: ").append(val).append(sep);
				break;
			case 0:
				sb.append("other: ").append(val).append(sep);
				break;
			case 3:
				sb.append("X.400: ").append(val).append(sep);
				break;
			case 5:
				sb.append("EDI party: ").append(val).append(sep);
				break;
			}
		}
	}
	
	/**
	 * Produces a human readable text representation of the provided certificate chain. 
	 * @param certChain input certificates
	 * @return the text representation
	 */
	public String format(X509Certificate[] certChain)
	{
		return format(certChain, true);
	}
	
	/**
	 * Produces a human readable text representation of the provided certificate chain. 
	 * @param certChain input certificates
	 * @param preamble whether to print a first line with an information on 
	 * the number of elements.
	 * @return the text representation
	 */
	public String format(X509Certificate[] certChain, boolean preamble)
	{
		StringBuilder sb = new StringBuilder();
		if (preamble)
			sb.append("Certificate chain, ").append(certChain.length).
					append(" elements:\n");
		for (int i=0; i<certChain.length; i++)
		{
			sb.append("-----Certificate ").append(i+1).append("-----\n");
			sb.append(format(certChain[i])).append("\n");
			if (i+1<certChain.length)
				sb.append("\n");
		}
		return sb.toString();
	}
}
