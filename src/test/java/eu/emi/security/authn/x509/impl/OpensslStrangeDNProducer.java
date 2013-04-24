/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.impl;

import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Hashtable;
import java.util.Set;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

import eu.emi.security.authn.x509.helpers.JavaAndBCStyle;
import eu.emi.security.authn.x509.helpers.proxy.X509v3CertificateBuilder;
import eu.emi.security.authn.x509.impl.CertificateUtils.Encoding;

/**
 * This class is really messy - it was used to generate test certificates with weird subjects, so we can use openssl
 * to get legacy form of this subject. 
 * @author K. Benedyczak
 */
public class OpensslStrangeDNProducer {
	static {
		CertificateUtils.configureSecProvider();
	}

	public static final ASN1ObjectIdentifier businessCategory = new ASN1ObjectIdentifier(
			"2.5.4.15");

	public static final ASN1ObjectIdentifier c = new ASN1ObjectIdentifier("2.5.4.6");

	public static final ASN1ObjectIdentifier cn = new ASN1ObjectIdentifier("2.5.4.3");

	public static final ASN1ObjectIdentifier dc = new ASN1ObjectIdentifier(
			"0.9.2342.19200300.100.1.25");

	public static final ASN1ObjectIdentifier description = new ASN1ObjectIdentifier("2.5.4.13");

	public static final ASN1ObjectIdentifier destinationIndicator = new ASN1ObjectIdentifier(
			"2.5.4.27");

	public static final ASN1ObjectIdentifier distinguishedName = new ASN1ObjectIdentifier(
			"2.5.4.49");

	public static final ASN1ObjectIdentifier dnQualifier = new ASN1ObjectIdentifier("2.5.4.46");

	public static final ASN1ObjectIdentifier enhancedSearchGuide = new ASN1ObjectIdentifier(
			"2.5.4.47");

	public static final ASN1ObjectIdentifier facsimileTelephoneNumber = new ASN1ObjectIdentifier(
			"2.5.4.23");

	public static final ASN1ObjectIdentifier generationQualifier = new ASN1ObjectIdentifier(
			"2.5.4.44");

	public static final ASN1ObjectIdentifier givenName = new ASN1ObjectIdentifier("2.5.4.42");

	public static final ASN1ObjectIdentifier houseIdentifier = new ASN1ObjectIdentifier(
			"2.5.4.51");

	public static final ASN1ObjectIdentifier initials = new ASN1ObjectIdentifier("2.5.4.43");

	public static final ASN1ObjectIdentifier internationalISDNNumber = new ASN1ObjectIdentifier(
			"2.5.4.25");

	public static final ASN1ObjectIdentifier l = new ASN1ObjectIdentifier("2.5.4.7");

	public static final ASN1ObjectIdentifier member = new ASN1ObjectIdentifier("2.5.4.31");

	public static final ASN1ObjectIdentifier name = new ASN1ObjectIdentifier("2.5.4.41");

	public static final ASN1ObjectIdentifier o = new ASN1ObjectIdentifier("2.5.4.10");

	public static final ASN1ObjectIdentifier ou = new ASN1ObjectIdentifier("2.5.4.11");

	public static final ASN1ObjectIdentifier owner = new ASN1ObjectIdentifier("2.5.4.32");

	public static final ASN1ObjectIdentifier physicalDeliveryOfficeName = new ASN1ObjectIdentifier(
			"2.5.4.19");

	public static final ASN1ObjectIdentifier postalAddress = new ASN1ObjectIdentifier(
			"2.5.4.16");

	public static final ASN1ObjectIdentifier postalCode = new ASN1ObjectIdentifier("2.5.4.17");

	public static final ASN1ObjectIdentifier postOfficeBox = new ASN1ObjectIdentifier(
			"2.5.4.18");

	public static final ASN1ObjectIdentifier preferredDeliveryMethod = new ASN1ObjectIdentifier(
			"2.5.4.28");

	public static final ASN1ObjectIdentifier registeredAddress = new ASN1ObjectIdentifier(
			"2.5.4.26");

	public static final ASN1ObjectIdentifier roleOccupant = new ASN1ObjectIdentifier("2.5.4.33");

	public static final ASN1ObjectIdentifier searchGuide = new ASN1ObjectIdentifier("2.5.4.14");

	public static final ASN1ObjectIdentifier seeAlso = new ASN1ObjectIdentifier("2.5.4.34");

	public static final ASN1ObjectIdentifier serialNumber = new ASN1ObjectIdentifier("2.5.4.5");

	public static final ASN1ObjectIdentifier sn = new ASN1ObjectIdentifier("2.5.4.4");

	public static final ASN1ObjectIdentifier st = new ASN1ObjectIdentifier("2.5.4.8");

	public static final ASN1ObjectIdentifier street = new ASN1ObjectIdentifier("2.5.4.9");

	public static final ASN1ObjectIdentifier telephoneNumber = new ASN1ObjectIdentifier(
			"2.5.4.20");

	public static final ASN1ObjectIdentifier teletexTerminalIdentifier = new ASN1ObjectIdentifier(
			"2.5.4.22");

	public static final ASN1ObjectIdentifier telexNumber = new ASN1ObjectIdentifier("2.5.4.21");

	public static final ASN1ObjectIdentifier title = new ASN1ObjectIdentifier("2.5.4.12");

	public static final ASN1ObjectIdentifier uid = new ASN1ObjectIdentifier(
			"0.9.2342.19200300.100.1.1");

	public static final ASN1ObjectIdentifier uniqueMember = new ASN1ObjectIdentifier("2.5.4.50");

	public static final ASN1ObjectIdentifier userPassword = new ASN1ObjectIdentifier("2.5.4.35");

	public static final ASN1ObjectIdentifier x121Address = new ASN1ObjectIdentifier("2.5.4.24");

	public static final ASN1ObjectIdentifier x500UniqueIdentifier = new ASN1ObjectIdentifier(
			"2.5.4.45");

	/**
	 * default look up table translating OID values into their common
	 * symbols following the convention in RFC 2253 with a few extras
	 */
	private static final Hashtable<ASN1ObjectIdentifier, String> DefaultSymbols = new Hashtable<ASN1ObjectIdentifier, String>();

	static {
		DefaultSymbols.put(businessCategory, "businessCategory");
		DefaultSymbols.put(c, "c");
		DefaultSymbols.put(cn, "cn");
		DefaultSymbols.put(dc, "dc");
		DefaultSymbols.put(description, "description");
		DefaultSymbols.put(destinationIndicator, "destinationIndicator");
		DefaultSymbols.put(distinguishedName, "distinguishedName");
		DefaultSymbols.put(dnQualifier, "dnQualifier");
		DefaultSymbols.put(enhancedSearchGuide, "enhancedSearchGuide");
		DefaultSymbols.put(facsimileTelephoneNumber, "facsimileTelephoneNumber");
		DefaultSymbols.put(generationQualifier, "generationQualifier");
		DefaultSymbols.put(givenName, "givenName");
		DefaultSymbols.put(houseIdentifier, "houseIdentifier");
		DefaultSymbols.put(initials, "initials");
		DefaultSymbols.put(internationalISDNNumber, "internationalISDNNumber");
		DefaultSymbols.put(l, "l");
		DefaultSymbols.put(member, "member");
		DefaultSymbols.put(name, "name");
		DefaultSymbols.put(o, "o");
		DefaultSymbols.put(ou, "ou");
		DefaultSymbols.put(owner, "owner");
		DefaultSymbols.put(physicalDeliveryOfficeName, "physicalDeliveryOfficeName");
		DefaultSymbols.put(postalAddress, "postalAddress");
		DefaultSymbols.put(postalCode, "postalCode");
		DefaultSymbols.put(postOfficeBox, "postOfficeBox");
		DefaultSymbols.put(preferredDeliveryMethod, "preferredDeliveryMethod");
		DefaultSymbols.put(registeredAddress, "registeredAddress");
		DefaultSymbols.put(roleOccupant, "roleOccupant");
		DefaultSymbols.put(searchGuide, "searchGuide");
		DefaultSymbols.put(seeAlso, "seeAlso");
		DefaultSymbols.put(serialNumber, "serialNumber");
		DefaultSymbols.put(sn, "sn");
		DefaultSymbols.put(st, "st");
		DefaultSymbols.put(street, "street");
		DefaultSymbols.put(telephoneNumber, "telephoneNumber");
		DefaultSymbols.put(teletexTerminalIdentifier, "teletexTerminalIdentifier");
		DefaultSymbols.put(telexNumber, "telexNumber");
		DefaultSymbols.put(title, "title");
		DefaultSymbols.put(uid, "uid");
		DefaultSymbols.put(uniqueMember, "uniqueMember");
		DefaultSymbols.put(userPassword, "userPassword");
		DefaultSymbols.put(x121Address, "x121Address");
		DefaultSymbols.put(x500UniqueIdentifier, "x500UniqueIdentifier");
	}

	public static X500Name generateDN() {
		int i = 5;
		AttributeTypeAndValue avas[][] = new AttributeTypeAndValue[i][];
		avas[0] = new AttributeTypeAndValue[] { new AttributeTypeAndValue(BCStyle.CN,
				new DERUTF8String("qweółą")) };
		avas[1] = new AttributeTypeAndValue[] { new AttributeTypeAndValue(BCStyle.C,
				new DERPrintableString("PL")) };
		ASN1ObjectIdentifier id = new ASN1ObjectIdentifier("2.5.4.3.3.2.222");
		avas[2] = new AttributeTypeAndValue[] { new AttributeTypeAndValue(id,
				new DERUTF8String(",\"\\+=<>;alaółąść")) };
		avas[3] = new AttributeTypeAndValue[] {
				new AttributeTypeAndValue(BCStyle.O, new DERPrintableString("zzz")),
				new AttributeTypeAndValue(BCStyle.C, new DERPrintableString("aaa")),
				new AttributeTypeAndValue(BCStyle.DC, new DERPrintableString("ggg"))};
		byte[] bb = new byte[2];
		for (byte k = -2; k < 0; k++)
			bb[k + 2] = k;
		avas[4] = new AttributeTypeAndValue[] { new AttributeTypeAndValue(id,
				new DERBitString(bb)) };

		RDN rdns[] = new RDN[i];
		for (int j = 0; j < i; j++)
			rdns[j] = new RDN(avas[j]);
		return new X500Name(rdns);
	}

	public static X500Name generateDN2() {
		int i = 0;
		AttributeTypeAndValue avas[] = new AttributeTypeAndValue[JavaAndBCStyle.asn2StringAll
				.size()];
		Set<ASN1ObjectIdentifier> keys = JavaAndBCStyle.asn2StringAll.keySet();
		for (ASN1ObjectIdentifier key : keys) {
			avas[i] = new AttributeTypeAndValue(key, new DERPrintableString(
					JavaAndBCStyle.asn2StringAll.get(key)));
			i++;
		}

		RDN rdns[] = new RDN[i];
		for (int j = 0; j < i; j++)
			rdns[j] = new RDN(avas[j]);
		return new X500Name(rdns);
	}

	public static X500Name generateDN3() {
		int i = 0;
		AttributeTypeAndValue avas[] = new AttributeTypeAndValue[DefaultSymbols.size()];
		Set<ASN1ObjectIdentifier> keys = DefaultSymbols.keySet();
		for (ASN1ObjectIdentifier key : keys) {
			avas[i] = new AttributeTypeAndValue(key, new DERPrintableString(
					(String) DefaultSymbols.get(key)));
			i++;
		}

		RDN rdns[] = new RDN[i];
		for (int j = 0; j < i; j++)
			rdns[j] = new RDN(avas[j]);
		return new X500Name(rdns);
	}

	public static void main(String... args) throws Exception {
		long now = System.currentTimeMillis();
		Date notBefore = new Date(now);
		Date notAfter = new Date(now + 1000 * 1000);
		BigInteger serial = new BigInteger("1234");

		X500Name issuer = generateDN();
		X500Name subject = issuer;

		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
		keyPairGen.initialize(1024, new SecureRandom());
		KeyPair kp = keyPairGen.generateKeyPair();

		SubjectPublicKeyInfo publicKeyInfo;
		ASN1InputStream is = new ASN1InputStream(kp.getPublic().getEncoded());
		publicKeyInfo = SubjectPublicKeyInfo.getInstance(is.readObject());
		is.close();

		X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(issuer, serial,
				notBefore, notAfter, subject, publicKeyInfo);

		String algName = "SHA1WithRSAEncryption";
		AlgorithmIdentifier algId = AlgorithmIdentifier.getInstance("1.2.840.113549.1.1.5");

		X509Certificate cert = certBuilder.build(kp.getPrivate(),
				algId,
				algName,
				null,
				null);
		System.out.println(cert.getSubjectX500Principal().getName());
		FileOutputStream fos = new FileOutputStream("target/cert-1.pem");
		CertificateUtils.saveCertificate(fos, cert, Encoding.PEM);
		fos.close();
	}
}
