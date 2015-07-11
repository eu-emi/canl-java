/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 * 
 * this work is derived from the implementation copyrighted and licensed as follows:
 * 
 * Copyright (c) 2000 - 2011 The Legion Of The Bouncy Castle (http://www.bouncycastle.org)
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
 * PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE
 * FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */
package eu.emi.security.authn.x509.helpers.proxy;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.V3TBSCertificateGenerator;

/**
 * Class to produce an X.509 Version 3 certificate. Based on the BC bcmail
 * library and deprecated class of the BC. We don't use BC mail 
 * as adding an another big dependency only for the certificate 
 * creation doesn't make much sense.
 */
public class X509v3CertificateBuilder
{
	private V3TBSCertificateGenerator tbsGen;
	private ExtensionsGenerator extGenerator;

	/**
	 * Create a builder for a version 3 certificate.
	 * 
	 * @param issuer the certificate issuer
	 * @param serial the certificate serial number
	 * @param notBefore the date before which the certificate is not valid
	 * @param notAfter the date after which the certificate is not valid
	 * @param subject the certificate subject
	 * @param publicKeyInfo the info structure for the public key to be associated
	 * with this certificate.
	 */
	public X509v3CertificateBuilder(X500Name issuer, BigInteger serial,
			Date notBefore, Date notAfter, X500Name subject,
			SubjectPublicKeyInfo publicKeyInfo)
	{
		tbsGen = new V3TBSCertificateGenerator();
		tbsGen.setSubject(subject);
		tbsGen.setSerialNumber(new ASN1Integer(serial));
		tbsGen.setIssuer(issuer);
		tbsGen.setStartDate(new Time(notBefore));
		tbsGen.setEndDate(new Time(notAfter));
		tbsGen.setSubject(subject);
		tbsGen.setSubjectPublicKeyInfo(publicKeyInfo);
		extGenerator = new ExtensionsGenerator();
	}

	/**
	 * Add a given extension field for the standard extensions tag (tag 3)
	 * 
	 * @param oid the OID defining the extension type.
	 * @param isCritical true if the extension is critical, false otherwise.
	 * @param value the ASN.1 structure that forms the extension's value.
	 * @return this builder object.
	 * @throws IOException 
	 */
	public X509v3CertificateBuilder addExtension(ASN1ObjectIdentifier oid,
			boolean isCritical, ASN1Object value) throws IOException
	{
		extGenerator.addExtension(oid, isCritical, value);
		return this;
	}

	/**
	 * Generate the certificate, signing it with the provided private key and
	 * using the specified algorithm. 
	 * @param key to be used for signing
	 * @param sigAlg oid and paramters  of the signature alg
	 * @param sigAlgName name of the signature alg
	 * @param provider can be null -&gt; default will be used
	 * @param random can be null -&gt; default will be used
	 * @return generated certificate
	 * @throws InvalidKeyException
	 * @throws CertificateParsingException
	 * @throws NoSuchProviderException
	 * @throws NoSuchAlgorithmException
	 * @throws SignatureException
	 * @throws IOException
	 */
	public X509Certificate build(PrivateKey key, AlgorithmIdentifier sigAlg,
			String sigAlgName, String provider, SecureRandom random) 
			throws InvalidKeyException, CertificateParsingException, 
			NoSuchProviderException, NoSuchAlgorithmException, 
			SignatureException, IOException
	{
		if (sigAlg == null || sigAlgName == null)
			throw new IllegalStateException(
					"no signature algorithm specified");
		if (key == null)
			throw new IllegalStateException(
					"no private key specified");
		tbsGen.setSignature(sigAlg);

		if (!extGenerator.isEmpty())
			tbsGen.setExtensions(extGenerator.generate());

		TBSCertificate toSign = tbsGen.generateTBSCertificate();
		return sign(toSign, sigAlg, sigAlgName, key, provider, random);
	}

	private X509Certificate sign(TBSCertificate toSign, AlgorithmIdentifier sigAlg, 
			String sigAlgName,
			PrivateKey key, String provider, SecureRandom random) 
		throws InvalidKeyException, NoSuchProviderException, NoSuchAlgorithmException, 
		SignatureException, IOException, CertificateParsingException
		
	{
		byte[] signature = calculateSignature(sigAlgName, 
				provider, key, random, toSign);

		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(toSign);
		v.add(sigAlg.toASN1Primitive());
		v.add(new DERBitString(signature));
		DERSequence derCertificate = new DERSequence(v);
		CertificateFactory factory;
		try
		{
			factory = CertificateFactory.getInstance("X.509");
			ByteArrayInputStream bais = new ByteArrayInputStream(derCertificate.getEncoded(ASN1Encoding.DER));
			return (X509Certificate) factory.generateCertificate(bais);
		} catch (CertificateException e)
		{
			throw new RuntimeException("The generated proxy " +
					"certificate was not parsed by the JDK", e);
		}
	}
	
	private byte[] calculateSignature(String sigName, String provider, PrivateKey key,
			SecureRandom random, ASN1Object object)
			throws IOException, NoSuchProviderException,
			NoSuchAlgorithmException, InvalidKeyException,
			SignatureException
	{
		Signature sig;

		if (provider != null)
			sig = Signature.getInstance(sigName, provider);
		else
			sig = Signature.getInstance(sigName);

		if (random != null)
			sig.initSign(key, random);
		else
			sig.initSign(key);

		sig.update(object.getEncoded(ASN1Encoding.DER));
		return sig.sign();
	}
	
	/**
	 * Extracts the full algorithm identifier from the given certificate.
	 * @param cert input certificate
	 * @return extracted algorithm id
	 * @throws IOException if parameters of the algorithm can not be parsed 
	 */
	public static AlgorithmIdentifier extractAlgorithmId(X509Certificate cert) 
			throws IOException
	{
		String oid = cert.getSigAlgOID();
		byte params[] = cert.getSigAlgParams();
		if (params != null)
		{
			ASN1Primitive derParams = ASN1Primitive.fromByteArray(params);
			return new AlgorithmIdentifier(new ASN1ObjectIdentifier(oid), 
					derParams);
		} else
		{
			return new AlgorithmIdentifier(new ASN1ObjectIdentifier(oid));
		}
	}
}
