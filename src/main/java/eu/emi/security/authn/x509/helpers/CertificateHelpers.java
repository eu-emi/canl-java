/*
 * Copyright (c) 2011 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.helpers;

import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;


/**
 * Utility methods for certificates handling and reading/writing PEM files.
 *
 * @author K. Benedyczak
 */
public class CertificateHelpers
{
	public enum PEMContentsType {PRIVATE_KEY, LEGACY_OPENSSL_PRIVATE_KEY, 
		CERTIFICATE, CSR, CRL, UNKNOWN};

	private static final byte[] TEST = new byte[] {1, 2, 3, 4, 100};
		
	/**
	 * Assumes that the input is the contents of the PEM identification line,
	 * after '-----BEGIN ' prefix.
	 *   
	 * @param name PEM first line to be checked.
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
		CertificateFactory factory = getFactory();
		try
		{
			return factory.generateCertificates(input);
		} catch (CertificateException e)
		{
			throw new IOException("Can not parse the input data as a certificate", e);
		} catch (ClassCastException e)
		{
			throw new IOException("Can not parse the input as it contains a certificate " +
					"but it is not an X.509 certificate.", e);
		} finally
		{
			input.close();
		}
	}

	public static Certificate readDERCertificate(InputStream input) throws IOException
	{
		CertificateFactory factory = getFactory();
		try
		{
			return factory.generateCertificate(input);
		} catch (CertificateException e)
		{
			throw new IOException("Can not parse the input data as a certificate", e);
		} catch (ClassCastException e)
		{
			throw new IOException("Can not parse the input as it contains a certificate " +
					"but it is not an X.509 certificate.", e);
		} finally
		{
			input.close();
		}
	}
	
	private static CertificateFactory getFactory()
	{
		try
		{
			return CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
		} catch (CertificateException e)
		{
			throw new RuntimeException("Can not initialize CertificateFactory, " +
					"your JDK installation is misconfigured!", e);
		} catch (NoSuchProviderException e)
		{
			throw new RuntimeException("Can not initialize CertificateFactory, " +
					"no BouncyCastle provider, it is a BUG!", e);
		}
	}
	
	/**
	 * Creates a chain of certificates, where the top-most certificate (the one without 
	 * issuing certificate) is the last in the returned array.
	 * @param certificates unsorted certificates of one chain
	 * @return sorted certificate chain
	 * @throws IOException if the passed chain is inconsistent
	 */
	public static X509Certificate[] sortChain(List<X509Certificate> certificates) throws IOException
	{
		if (certificates.size() == 0)
			return new X509Certificate[0];
		
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
		
		return certsList.toArray(new X509Certificate[certsList.size()]);
	}
	
	/**
	 * Converts certificates array to {@link CertPath}
	 * @param in array
	 * @return converted object
	 * @throws CertificateException certificate exception
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
		return X500Name.getInstance(style, withDefaultStyle);
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
		DEROctetString valueOctets = (DEROctetString) ASN1Primitive
				.fromByteArray(bytes);
		return valueOctets.getOctets();
	}
	
	/**
	 * Throws an exception if the private key is not matching the public key.
	 * The check is done only for known types of keys - RSA and DSA currently.
	 * @param privKey first key to match
	 * @param pubKey 2nd key to match
	 * @throws InvalidKeyException invalid key exception
	 */
	public static void checkKeysMatching(PrivateKey privKey, PublicKey pubKey) throws InvalidKeyException
	{
		String algorithm = pubKey.getAlgorithm();
		if (!privKey.getAlgorithm().equals(algorithm))
			throw new InvalidKeyException("Private and public keys are not matching: different algorithms");
		
		if (algorithm.equals("DSA"))
		{
			if (!checkKeysViaSignature("SHA1withDSA", privKey, pubKey))
				throw new InvalidKeyException("Private and public keys are not matching: DSA");
		} else if (algorithm.equals("RSA")) 
		{
			RSAPublicKey rpub = (RSAPublicKey)pubKey;
			RSAPrivateKey rpriv = (RSAPrivateKey)privKey;
			if (!rpub.getModulus().equals(rpriv.getModulus()))
				throw new InvalidKeyException("Private and public keys are not matching: RSA parameters");
		} else if (algorithm.equals("GOST3410")) 
		{
			if (!checkKeysViaSignature("GOST3411withGOST3410", privKey, pubKey))
				throw new InvalidKeyException("Private and public keys are not matching: GOST 34.10");
		} else if (algorithm.equals("ECGOST3410")) 
		{
			if (!checkKeysViaSignature("GOST3411withECGOST3410", privKey, pubKey))
				throw new InvalidKeyException("Private and public keys are not matching: EC GOST 34.10");
		} else if (algorithm.equals("ECDSA")) 
		{
			if (!checkKeysViaSignature("SHA1withECDSA", privKey, pubKey))
				throw new InvalidKeyException("Private and public keys are not matching: EC DSA");
		}
	}
	
	private static boolean checkKeysViaSignature(String alg, PrivateKey privKey, PublicKey pubKey) throws InvalidKeyException
	{
		try
		{
			Signature s = Signature.getInstance(alg);
			s.initSign(privKey);
			s.update(TEST);
			byte[] signature = s.sign();
			Signature s2 = Signature.getInstance(alg);
			s2.initVerify(pubKey);
			s2.update(TEST);
			return s2.verify(signature);
		} catch (NoSuchAlgorithmException e)
		{
			throw new RuntimeException("Bug: BC provider not available in checkKeysMatching()", e);
		} catch (SignatureException e)
		{
			throw new RuntimeException("Bug: can't sign/verify test data", e);
		}
	}
}





