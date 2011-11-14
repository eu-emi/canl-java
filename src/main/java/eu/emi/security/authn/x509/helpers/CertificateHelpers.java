/*
 * Copyright (c) 2011 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.helpers;

import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchProviderException;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x500.X500Name;


/**
 * Utility methods for certificates handling and reading/writing PEM files.
 *
 * @author K. Benedyczak
 */
public class CertificateHelpers
{
	public enum PEMContentsType {PRIVATE_KEY, LEGACY_OPENSSL_PRIVATE_KEY, 
		CERTIFICATE, CSR, CRL, UNKNOWN};

	/**
	 * Assumes that the input is the contents of the PEM identification line,
	 * after '-----BEGIN ' prefix.
	 *   
	 * @param pem PEM string to be checked.
	 * @return the type
	 */
	public static PEMContentsType getPEMType(String name)
	{
		if (name.contains("CERTIFICATE") && !name.contains("REQUEST"))
			return PEMContentsType.CERTIFICATE;
		if (name.equals("PRIVATE KEY"))
			return PEMContentsType.PRIVATE_KEY;
		if (name.equals("ENCRYPTED PRIVATE KEY"))
			return PEMContentsType.PRIVATE_KEY;
		if (name.contains("PRIVATE KEY"))
			return PEMContentsType.LEGACY_OPENSSL_PRIVATE_KEY;
		if (name.contains("REQUEST") && name.contains("CERTIFICATE"))
			return PEMContentsType.CSR;
		if (name.contains("CRL"))
			return PEMContentsType.CRL;
		return PEMContentsType.UNKNOWN;
	}

	
	public static Collection<? extends Certificate> readDERCertificates(InputStream input) throws IOException
	{
		CertificateFactory factory;
		try
		{
			factory = CertificateFactory.getInstance("X.509", "BC");
		} catch (CertificateException e)
		{
			throw new RuntimeException("Can not initialize CertificateFactory, " +
					"your JDK installation is misconfigured!", e);
		} catch (NoSuchProviderException e)
		{
			throw new RuntimeException("Can not initialize CertificateFactory, " +
					"no BouncyCastle provider, it is a BUG!", e);
		}
		Collection<? extends Certificate> ret;
		try
		{
			ret = factory.generateCertificates(input);
		} catch (CertificateException e)
		{
			throw new IOException("Can not parse the input data as a certificate", e);
		} catch (ClassCastException e)
		{
			throw new IOException("Can not parse the input as it contains a certificate " +
					"but it is not an X.509 certificate.", e);
		}
		
		return ret;
	}
	
	/**
	 * Creates a chain of certificates, where the top-most certificate (the one without 
	 * issuing certificate) is the last in the returned array.
	 * @param certificates unsorted certificates of one chain
	 * @return sorted certificate chain
	 * @throws IOException if the passed chain is inconsistent
	 */
	public static Certificate[] sortChain(List<X509Certificate> certificates) throws IOException
	{
		if (certificates.size() == 0)
			return new Certificate[0];
		
		Map<X500Principal, X509Certificate> certsMapBySubject = new HashMap<X500Principal, X509Certificate>();
		//in this map root CA cert is not stored (as it has the same Issuer as its direct child)
		Map<X500Principal, X509Certificate> certsMapByIssuer = new HashMap<X500Principal, X509Certificate>();
		for (X509Certificate c: certificates) 
		{
			certsMapBySubject.put(c.getSubjectX500Principal(), c);
			if (!c.getIssuerX500Principal().equals(c.getSubjectX500Principal()))
				certsMapByIssuer.put(c.getIssuerX500Principal(), c);
		}

		//let's start from the random one (the 1st on the received list)
		List<X509Certificate> certsList = new LinkedList<X509Certificate>();
		X509Certificate current = certsMapBySubject.remove(certificates.get(0).getSubjectX500Principal());
		if (!current.getIssuerX500Principal().equals(current.getSubjectX500Principal()))
			certsMapByIssuer.remove(current.getIssuerX500Principal());
		certsList.add(current);

		//build path from current to root
		while (true)
		{
			X509Certificate parent = certsMapBySubject.remove(current.getIssuerX500Principal());
			if (parent != null)
			{
				certsMapByIssuer.remove(parent.getIssuerX500Principal());
				certsList.add(parent);
				current = parent;
			} else
				break;
		}
		
		//build path from the first on the list down to the user's certificate
		current = certsList.get(0);
		while (true)
		{
			X509Certificate child = certsMapByIssuer.remove(current.getSubjectX500Principal());
			if (child != null)
			{
				certsList.add(0, child);
				current = child;
			} else
				break;
		}
		
		if (certsMapByIssuer.size() > 0)
			throw new IOException("The keystore is inconsistent as it contains certificates from different chains");
		
		Certificate []ret = new Certificate[certificates.size()];
		for (int i=0; i<certsList.size(); i++)
			ret[i] = certsList.get(i);
		return ret;
	}
	
	/**
	 * Converts certificates array to {@link CertPath}
	 * @param in array
	 * @return converted object
	 * @throws CertificateException
	 */
	public static CertPath toCertPath(X509Certificate[] in) throws CertificateException
	{
		CertificateFactory certFactory;
		try
		{
			certFactory = CertificateFactory.getInstance("X.509");
		} catch (CertificateException e)
		{
			throw new RuntimeException("No provider supporting X.509 " +
					"CertificateFactory. JDK is misconfigured?", e);
		}
		return certFactory.generateCertPath(Arrays.asList(in));
	}
	
	/**
	 * Converts {@link X500Principal} to {@link X500Name} with the {@link JavaAndBCStyle}
	 * style.
	 * @param srcDn source object
	 * @return converted object
	 */
	public static X500Name toX500Name(X500Principal srcDn)
	{
		X500Name withDefaultStyle = X500Name.getInstance(srcDn.getEncoded());
		JavaAndBCStyle style = new JavaAndBCStyle();
		return new X500Name(style, withDefaultStyle);
	}

	/**
	 * Gets the certificate extension identified by the oid and returns the
	 * value bytes unwrapped by the ASN1OctetString.
	 * 
	 * @param cert
	 *                The certificate to inspect.
	 * @param oid
	 *                The extension OID to fetch.
	 * @return The value bytes of the extension, returns null in case the
	 *         extension was not present or was empty.
	 * @throws IOException
	 *                 thrown in case the certificate parsing fails.
	 */
	public static byte[] getExtensionBytes(X509Certificate cert, String oid)
			throws IOException
	{
		byte[] bytes = cert.getExtensionValue(oid);
		if (bytes == null)
			return null;
		DEROctetString valueOctets = (DEROctetString) ASN1Object
				.fromByteArray(bytes);
		return valueOctets.getOctets();
	}
	
	/**
	 *
	 * @see #opensslToRfc2253(String, boolean) with second arg equal to false
	 * @param inputDN
	 * @return
	 */
	public static String opensslToRfc2253(String inputDN) 
	{
		return opensslToRfc2253(inputDN, false);
	}
	
	/**
	 * Tries to convert the OpenSSL string representation
	 * of a DN into a RFC 2253 form. The conversion is as follows:
	 * (1) the string is split on '/',
	 * (2) all resulting parts which have no '=' sign inside are glued with the previous element
	 * (3) parts are outputted with ',' as a separator in reversed order.
	 * @param inputDN
	 * @param withWildcards whether '*' wildcards need to be recognized
	 * @return
	 */
	public static String opensslToRfc2253(String inputDN, boolean withWildcards) 
	{
		if (inputDN.length() < 2 || !inputDN.startsWith("/"))
			throw new IllegalArgumentException("The string '" + inputDN +
					"' is not a valid OpenSSL-encoded DN");
		inputDN = inputDN.replace(",", "\\,");
		String[] parts = inputDN.split("/");

		if (parts.length < 2)
			return inputDN.substring(1);

		List<String> avas = new ArrayList<String>();
		avas.add(parts[1]);
		for (int i=2, j=0; i<parts.length; i++)
		{
			if (!(parts[i].contains("=") || (withWildcards && parts[i].contains("*"))))
			{
				String cur = avas.get(j);
				avas.set(j, cur+"/"+parts[i]);
			} else
			{
				avas.add(++j, parts[i]);
			}
		}

		StringBuilder buf = new StringBuilder();
		for (int i=avas.size()-1; i>0; i--)
			buf.append(avas.get(i)).append(",");
		buf.append(avas.get(0));
		return buf.toString();
	}

}
