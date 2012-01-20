/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.impl;

import java.io.IOException;
import java.security.KeyStoreException;
import java.util.Collections;
import java.util.List;

import eu.emi.security.authn.x509.CrlCheckingMode;
import eu.emi.security.authn.x509.X509CertChainValidator;
import eu.emi.security.authn.x509.helpers.pkipath.PlainCRLValidator;
import eu.emi.security.authn.x509.helpers.trust.DirectoryTrustAnchorStore;
import eu.emi.security.authn.x509.impl.CertificateUtils.Encoding;

/**
 * The certificate validator which uses a flexible set of certificates and CRL locations.
 * Both CA certificates or CRLs can be provided as a list of locations. Each element 
 * in the list is either a URL to a concrete file (note that this might be remote file)
 * or a local path. In the latter case it is possible to use wildcards in path locations.
 * <p>
 * It is possible to configure this validator to refresh both CRL and CA 
 * certificate locations on a regular interval.
 * <p>
 * Note: be very careful when using remote CA certificate locations. If such a remote 
 * location is compromised or DNS address is spooffed then your system is also compromised.  
 * <p>
 * It is possible to configure this validator to use files encoded in DER or PEM format, 
 * but all the files must use a single encoding.
 * <p>
 * The CRLs (Certificate Revocation Lists, if their handling is turned on) can be obtained
 * also from the CA certificate extension defining CRL URL if are not provided explicitly.
 * 
 * @author K. Benedyczak
 * @see X509CertChainValidator
 */
public class DirectoryCertChainValidator extends PlainCRLValidator
{
	private DirectoryTrustAnchorStore trustStore;
	
	/**
	 * Constructs a new validator instance. CRLs (Certificate Revocation Lists) 
	 * are taken from the trusted CAs certificate extension and downloaded, 
	 * unless CRL checking is disabled. Additional CRLs may be provided manually.  
	 * 
	 * @param trustedLocations trusted certificates locations, either as local wildcard
	 * paths or URLs
	 * @param encoding Whether certificates in the store are stored as PEM or DER files. Note that the
	 * whole store must be consistent.
	 * @param truststoreUpdateInterval truststore update interval in milliseconds
	 * @param connectionTimeoutCA connection timeout in ms for downloading remote CA certificates, >= 0. 0 means infinite timeout. 
	 * @param diskCache directory path, where the remote CA certificates shall be cached 
	 * after downloading. Can be null if cache shall not be used.
	 * @param params common validator settings (revocation, initial listeners, proxy support, ...)
	 * @throws IOException 
	 * @throws KeyStoreException 
	 */
	public DirectoryCertChainValidator(List<String> trustedLocations, Encoding encoding,
			long truststoreUpdateInterval, int connectionTimeoutCA, 
			String diskCache, ValidatorParamsExt params) 
					throws KeyStoreException, IOException 
	{
		super(params.getRevocationSettings(), params.getInitialListeners());
		trustStore = new DirectoryTrustAnchorStore(trustedLocations, diskCache, 
				connectionTimeoutCA, timer, truststoreUpdateInterval, encoding, 
				params.getInitialListeners());
		init(trustStore, crlStoreImpl, params.isAllowProxy(), params.getRevocationSettings());
	}
	
	/**
	 * Constructs a new validator instance with default additional settings
	 * (see {@link ValidatorParamsExt#ValidatorParamsExt()}).
	 * 
	 * @param trustedLocations trusted certificates locations, either as local wildcard
	 * paths or URLs
	 * @param encoding Whether certificates in the store are stored as PEM or DER files. Note that the
	 * whole store must be consistent.
	 * @param truststoreUpdateInterval truststore update interval in milliseconds
	 * @param connectionTimeoutCA connection timeout in ms for downloading remote CA certificates, >= 0. 0 means infinite timeout. 
	 * @param diskCache directory path, where the remote CA certificates shall be cached 
	 * after downloading. Can be null if cache shall not be used.
	 * @throws IOException 
	 * @throws KeyStoreException 
	 */
	public DirectoryCertChainValidator(List<String> trustedLocations, Encoding encoding,
			long truststoreUpdateInterval, int connectionTimeoutCA, 
			String diskCache) throws KeyStoreException, IOException 
	{
		this(trustedLocations, encoding, truststoreUpdateInterval, 
				connectionTimeoutCA, diskCache, 
				new ValidatorParamsExt());
	}
	
	/**
	 * 
	 * Constructs a new validator instance with simplified parameters: only one location for 
	 * certificates and CRLs, CRLs are checked if present, truststore and CRLs are refreshed 
	 * every hour, connection timeout is 15s, proxies are supported, encoding is PEM and no initial 
	 * update listener is registered. 
	 * 
	 * @param trustedLocation trusted certificates location, either as local wildcard
	 * path or URL
	 * @param crlLocation location of CRLs, either as local wildcard
	 * path or URL.
	 * @param diskCache directory path, where the remote CA certificates shall be cached 
	 * after downloading. Can be null if cache shall not be used.
	 * @throws IOException 
	 * @throws KeyStoreException 
	 */
	public DirectoryCertChainValidator(String trustedLocation, String crlLocation, 
			String diskCache) 
				throws KeyStoreException, IOException 
	{
		this(Collections.singletonList(trustedLocation), Encoding.PEM,
			3600000, 15000, diskCache, 
			new ValidatorParamsExt(
				new RevocationParametersExt(CrlCheckingMode.IF_VALID,
						new CRLParameters(Collections.singletonList(crlLocation), 
						3600000, 15000, diskCache)), 
				ValidatorParams.DEFAULT_PROXY_SUPPORT));
	}

	
	/**
	 * Returns the interval between subsequent checks of the truststore files. 
	 * @return the current refresh interval in milliseconds
	 */
	public long getTruststoreUpdateInterval()
	{
		return trustStore.getUpdateInterval();
	}

	/**
	 * Sets a new interval between subsequent checks of the truststore
	 * files. 
	 * @param updateInterval the new interval to be set in milliseconds
	 */
	public void setTruststoreUpdateInterval(long updateInterval)
	{
		trustStore.setUpdateInterval(updateInterval);
	}

	/**
	 * Returns the current truststore locations
	 * @return the path
	 */
	public List<String> getTruststorePaths()
	{
		return trustStore.getLocations();
	}
	
	/**
	 * Sets new trusted locations. See constructor argument description
	 * for details.
	 */
	public void setTruststorePaths(List<String> trustedLocations)
	{
		trustStore.dispose();
		trustStore = new DirectoryTrustAnchorStore(trustedLocations, 
				trustStore.getCacheDir(), trustStore.getConnTimeout(), 
				timer, trustStore.getUpdateInterval(), 
				trustStore.getEncoding(), observers);
		init(trustStore, null, isProxyAllowed(), getRevocationCheckingMode());
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void dispose()
	{
		super.dispose();
		trustStore.dispose();
	}
}






