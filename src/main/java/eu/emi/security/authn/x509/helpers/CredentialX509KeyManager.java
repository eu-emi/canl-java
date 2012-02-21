/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers;

import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;

import eu.emi.security.authn.x509.X509Credential;

/**
 * Simple {@link KeyManager} implementation which always returns the only key and certificate
 * which is available in the configured {@link X509Credential} object.
 * Note that this class could return null in case when server provides 
 * a list of trusted issuers and our credential is not issued by any of them. However
 * such behavior results in quite cryptic errors from the server side ("null cert chain"),
 * so we try to authenticate with what we have always.  
 * 
 * @author K. Benedyczak
 */
public class CredentialX509KeyManager extends X509ExtendedKeyManager
{
	private X509Credential credential; 
	
	
	public CredentialX509KeyManager(X509Credential credential)
	{
		this.credential = credential;
	}

	@Override
	public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket)
	{
		return credential.getKeyAlias();
	}

	@Override
	public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket)
	{
		return credential.getKeyAlias();
	}

	@Override
	public X509Certificate[] getCertificateChain(String alias)
	{
		return credential.getCertificateChain();
	}

	@Override
	public String[] getClientAliases(String keyType, Principal[] issuers)
	{
		return new String[] {credential.getKeyAlias()};
	}

	@Override
	public PrivateKey getPrivateKey(String alias)
	{
		return credential.getKey();
	}

	@Override
	public String[] getServerAliases(String keyType, Principal[] issuers)
	{
		return new String[] {credential.getKeyAlias()};
	}

	@Override
	public String chooseEngineClientAlias(String[] keyType, Principal[] issuers, 
			SSLEngine engine)
	{
		return credential.getKeyAlias();
	}

	@Override
	public String chooseEngineServerAlias(String keyType, Principal[] issuers, 
			SSLEngine engine)
	{
		return credential.getKeyAlias();
	}
}
