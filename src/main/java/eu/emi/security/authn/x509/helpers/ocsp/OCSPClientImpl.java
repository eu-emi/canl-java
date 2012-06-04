/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.ocsp;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Random;
import java.util.Vector;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.CertificateID;
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.ocsp.OCSPReq;
import org.bouncycastle.ocsp.OCSPReqGenerator;
import org.bouncycastle.ocsp.OCSPResp;
import org.bouncycastle.ocsp.SingleResp;

import eu.emi.security.authn.x509.X509Credential;
import eu.emi.security.authn.x509.impl.CertificateUtils;
import eu.emi.security.authn.x509.impl.FormatMode;

/**
 * OCSP client is responsible for the network related activity of the OCSP invocation pipeline.
 * This class is state less and thread safe.
 * @author K. Benedyczak
 */
public class OCSPClientImpl
{
	private static final int MAX_RESPONSE_SIZE = 20480;
	
	/**
	 * Returns a verified single response, related to the checked certificate. This is single-shot version, 
	 * which can be used instead of manual invocation of low-level methods.
	 * @param responder mandatory - URL of the responder. HTTP or HTTPs, however in https mode the 
	 * @param toCheckCert mandatory certificate to be checked
	 * @param issuerCert mandatory certificate of the toCheckCert issuer
	 * @param requester if not null, then it is assumed that request must be signed by the requester.
	 * @param addNonce if true nonce will be added to the request and required in response
	 * @return Final OCSP checking result
	 * @throws OCSPException 
	 */
	public OCSPResult queryForCertificate(URL responder, X509Certificate toCheckCert, 
			X509Certificate issuerCert, X509Credential requester, boolean addNonce, int timeout) 
					throws IOException, OCSPException 
	{
		OCSPReq request = createRequest(toCheckCert, issuerCert, requester, addNonce);
		OCSPResp response = send(responder, request, timeout);
		byte[] nonce = null;
		if (addNonce)
			nonce = extractNonce(request);
		SingleResp resp = verifyResponse(response, toCheckCert, issuerCert, nonce);
		return new OCSPResult(resp);
	}


	public OCSPReq createRequest(X509Certificate toCheckCert, 
			X509Certificate issuerCert, X509Credential requester, boolean addNonce) 
					throws OCSPException
	{
		OCSPReqGenerator generator = new OCSPReqGenerator();
		CertificateID certId = new CertificateID(CertificateID.HASH_SHA1, issuerCert, 
				toCheckCert.getSerialNumber());
		generator.addRequest(certId);
		if (addNonce)
		{
			Vector<ASN1ObjectIdentifier> oids = new Vector<ASN1ObjectIdentifier>();
			Vector<X509Extension> values = new Vector<X509Extension>();
			byte[] nonce = new byte[16];
			Random rand = new Random();
			rand.nextBytes(nonce);

			oids.addElement(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
			values.addElement(new X509Extension(false, new DEROctetString(nonce)));
			generator.setRequestExtensions(new X509Extensions(oids, values));
		}
		if (requester != null)
		{
			generator.setRequestorName(requester.getCertificate().getSubjectX500Principal());
			try
			{
				return generator.generate(requester.getCertificate().getSigAlgOID(), requester.getKey(), 
						null, BouncyCastleProvider.PROVIDER_NAME);
			} catch (NoSuchProviderException e)
			{
				throw new RuntimeException("Bug: BC provider not initialized", e);
			} catch (IllegalArgumentException e)
			{
				throw new OCSPException("Unsupported signing algorithm when creating a OCSP request?", e);
			}
		} else
		{
			return generator.generate();
		}
	}
	
	public OCSPResp send(URL responder, OCSPReq requestO, int timeout) throws IOException {
		InputStream in = null;
		OutputStream out = null;
		byte[] request = requestO.getEncoded();
		byte[] response = null;
		try {
			HttpURLConnection con = (HttpURLConnection) responder.openConnection();
			con.setConnectTimeout(timeout);
			con.setReadTimeout(timeout);
			con.setDoOutput(true);
			con.setRequestMethod("POST");
			con.setRequestProperty("Content-type", "application/ocsp-request");
			con.setRequestProperty("Content-length", String.valueOf(request.length));
			out = con.getOutputStream();
			out.write(request);
			out.flush();

			in = con.getInputStream();
			int contentLength = con.getContentLength();
			if (contentLength == -1 || contentLength > MAX_RESPONSE_SIZE)
				contentLength = MAX_RESPONSE_SIZE;

			response = new byte[contentLength];
			int total = 0;
			int count = 0;
			while (total < contentLength) {
				count = in.read(response, total, response.length - total);
				if (count < 0)
					break;

				total += count;
			}
			if (count >= 0 && in.read() >= 0)
				throw new IOException("OCSP response size exceeded the upper limit of " + 
						MAX_RESPONSE_SIZE);
			if (total != contentLength)
				response = Arrays.copyOf(response, total);
		} finally {
			if (in != null) {
				try {
					in.close();
				} catch (IOException ioe) {
					throw ioe;
				}
			}
			if (out != null) {
				try {
					out.close();
				} catch (IOException ioe) {
					throw ioe;
				}
			}
		}
		return new OCSPResp(response);
	}
	
	private static String getResponderErrorDesc(int errorNo)
	{
		switch (errorNo)
		{
		case OCSPResponseStatus.INTERNAL_ERROR:
			return "internal server error";
		case OCSPResponseStatus.MALFORMED_REQUEST:
			return "malformed request";
		case OCSPResponseStatus.SIG_REQUIRED:
			return "request is required to be signed";
		case OCSPResponseStatus.TRY_LATER:
			return "try again later";
		case OCSPResponseStatus.UNAUTHORIZED:
			return "request was not authorized";
		default:
			return "unknown error";
		
		}
	}
	
	/**
	 * Verifies the provided response
	 * @param response
	 * @param toCheckCert
	 * @param issuerCert
	 * @param checkNonce
	 * @return verified response corresponding to the certificate being checked
	 * @throws OCSPException
	 */
	public SingleResp verifyResponse(OCSPResp response, X509Certificate toCheckCert,
			X509Certificate issuerCert, byte[] checkNonce) throws OCSPException
	{
		if (response.getStatus() != OCSPResponseStatus.SUCCESSFUL)
			throw new OCSPException("Responder returned an error: " + 
					getResponderErrorDesc(response.getStatus()));  		
		Object respO = response.getResponseObject();
		if (!(respO instanceof BasicOCSPResp))
				throw new OCSPException("Only Basic OCSP response type is supported");
		BasicOCSPResp bresp = (BasicOCSPResp) respO;
		
		//version, producedAt and responderID are ignored.
		if (checkNonce != null)
		{
			byte[] nonceAsn = bresp.getExtensionValue(OCSPObjectIdentifiers.id_pkix_ocsp_nonce.getId());
			if (nonceAsn == null)
				throw new OCSPException("Nonce was sent and is required but did not get it in reply");
			ASN1OctetString octs;
			try
			{
				octs = (ASN1OctetString)ASN1Object.fromByteArray(nonceAsn);
			} catch (Exception e)
			{
				throw new OCSPException("Nonce received with the reply is invalid, " +
						"unable to parse it", e);
			}
			byte[] nonce = octs.getOctets();
			if (!Arrays.equals(nonce, checkNonce))
				throw new OCSPException("Received nonce doesn't match the one sent to the server. " +
						"Sent: " + Arrays.toString(checkNonce) + " received: " + 
						Arrays.toString(nonce));
		}

		PublicKey key = establishResponsePubKey(bresp, issuerCert);
		try
		{
			if (!bresp.verify(key, BouncyCastleProvider.PROVIDER_NAME))
				throw new OCSPException("Failed to verify the OCSP response signature. " +
						"It is corrupted or faked");
		} catch (NoSuchProviderException e)
		{
			throw new RuntimeException("Bug, BC provider is not available?", e);
		}
		
		if (bresp.hasUnsupportedCriticalExtension())
			throw new OCSPException("OCSP contains unsupported critical extensions: " + 
					bresp.getCriticalExtensionOIDs());
		
		SingleResp[] resps = bresp.getResponses();
		for (int i=0; i<resps.length; i++)
		{
			SingleResp sResp = resps[i];
			if (sResp.hasUnsupportedCriticalExtension())
				throw new OCSPException("OCSP SingleResponse contains unsupported critical extensions: " + 
						sResp.getCriticalExtensionOIDs());
			
			if (!checkCertIDMatching(toCheckCert, issuerCert, sResp.getCertID()))
				continue;
		
			verifyTimeRange(sResp.getThisUpdate(), sResp.getNextUpdate());

			return sResp;
		}
		throw new OCSPException("Received a correct answer from OCSP responder, but it didn't contain " +
				"any information on the certificate being checked");
	}
	
	private void verifyTimeRange(Date thisUpdate, Date nextUpdate) throws OCSPException
	{
		Date now = new Date();
		if (thisUpdate == null)
			throw new OCSPException("Malformed OCSP response, no thisUpdate time");
		int tolerance = 120000; //two minutes
		
		Date futureNow = new Date(now.getTime() + tolerance);
		Date pastNow = new Date(now.getTime() - tolerance);

		if (futureNow.before(thisUpdate))
			throw new OCSPException("Response is not yet valid, will be from: " + thisUpdate);
			
		if (nextUpdate != null && pastNow.after(nextUpdate))
			throw new OCSPException("Response has expired on: " + nextUpdate);
	}
	
	private boolean checkCertIDMatching(X509Certificate toFind, X509Certificate issuerCert, 
			CertificateID checkedCertId) throws OCSPException
	{
		CertificateID certId = new CertificateID(checkedCertId.getHashAlgOID(), issuerCert, 
				toFind.getSerialNumber());
		return certId.equals(checkedCertId);
	}
	
	private PublicKey establishResponsePubKey(BasicOCSPResp bresp, X509Certificate issuerCert) throws OCSPException
	{
		X509Certificate[] signerCerts;
		try
		{
			signerCerts = bresp.getCerts(BouncyCastleProvider.PROVIDER_NAME);
		} catch (NoSuchProviderException e)
		{
			throw new RuntimeException("Bug, BC provider is not available?", e);
		}
		if (signerCerts == null || signerCerts.length == 0)
			return issuerCert.getPublicKey();
		X509Certificate signerCert = signerCerts[0];
		if (signerCert.equals(issuerCert))
			return issuerCert.getPublicKey();
		
		//ok - now we have the last possibility - delegated OCSP responder
		if (!issuerCert.getSubjectX500Principal().equals(signerCert.getIssuerX500Principal()))
			throw new OCSPException("Response is signed by an untrusted/invalid entity: " +
					CertificateUtils.format(signerCert, FormatMode.COMPACT_ONE_LINE));
		try
		{
			List<String> keyUsage = signerCert.getExtendedKeyUsage();
			if (keyUsage == null || !keyUsage.contains(KeyPurposeId.id_kp_OCSPSigning.getId())) 
				throw new OCSPException("Response is signed by an entity which does not have the " +
						"OCSP delegation from the CA (no flag in ExtendedKeyUsage)");
		} catch (CertificateParsingException e)
		{
			throw new OCSPException("Response contains an unparsable certificate (ExtendedKeyUsage)", e);
		}

		try
		{
			signerCert.verify(issuerCert.getPublicKey(), BouncyCastleProvider.PROVIDER_NAME);
		} catch (Exception e)
		{
			throw new OCSPException("Response contains a certificate which is improperly signed, " +
					"it is faked or corrupted: " + e.getMessage(), e);
		}
		
		return signerCert.getPublicKey();	
	}
	
	
	public static byte[] extractNonce(OCSPReq request)
	{
		byte[] nonceAsn = request.getExtensionValue(OCSPObjectIdentifiers.id_pkix_ocsp_nonce.getId());
		if (nonceAsn == null)
			return null;
		ASN1OctetString octs;
		try
		{
			octs = (ASN1OctetString)ASN1Object.fromByteArray(nonceAsn);
		} catch (Exception e)
		{
			throw new IllegalStateException("Can't decode nonce encoded in request", e);
		}
		return octs.getOctets();			
	}
}











