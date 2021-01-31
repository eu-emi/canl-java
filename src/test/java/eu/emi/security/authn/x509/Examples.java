/*
 * Copyright (c) 2011 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509;

import java.io.InputStream;
import java.net.ServerSocket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.net.ssl.SSLServerSocketFactory;
import javax.security.auth.x500.X500Principal;

import eu.emi.security.authn.x509.impl.CRLParameters;
import eu.emi.security.authn.x509.impl.CertificateUtils;
import eu.emi.security.authn.x509.impl.HostnameMismatchCallback2;
import eu.emi.security.authn.x509.impl.CertificateUtils.Encoding;
import eu.emi.security.authn.x509.impl.KeystoreCertChainValidator;
import eu.emi.security.authn.x509.impl.KeystoreCredential;
import eu.emi.security.authn.x509.impl.OpensslCertChainValidator;
import eu.emi.security.authn.x509.impl.RevocationParametersExt;
import eu.emi.security.authn.x509.impl.SocketFactoryCreator2;
import eu.emi.security.authn.x509.impl.ValidatorParams;
import eu.emi.security.authn.x509.impl.ValidatorParamsExt;
import eu.emi.security.authn.x509.impl.X500NameUtils;

/**
 * Contains example code which is used in documentation - mostly to check its syntax.
 * @author K. Benedyczak
 */
@SuppressWarnings("unused")
public class Examples
{
//!!!formating is intended!!!!
	
	public void example1() throws Exception
	{
		
/*
 * Validates toBeChecked chain using Openssl style truststore, from
 * the /etc/grid-security/certificates directory. Both kinds of 
 * namespaces are checked and forced if are present. Truststore is 
 * reread every minute. The additional settings are not defined and
 * so defaults are used: CRLs are forced if are present. Proxy 
 * certificates are supported. No listeners are registered to 
 * be notified about trusted CA certificates, CRLs or namespace 
 * definitions reloading.
 */
X509Certificate[] toBeChecked = null;
X509CertChainValidator vff = new OpensslCertChainValidator(
	"/etc/grid-security/certificates", 
	NamespaceCheckingMode.EUGRIDPMA_AND_GLOBUS, 60000);

ValidationResult result = vff.validate(toBeChecked);
if (result.isValid()) {
	//...
} else {
	List<ValidationError> errors = result.getErrors();
	//...
}
	
	}
	
	public void example2() throws Exception
	{
/*
 * A more complicated example. SSL sockets will be created with the
 * certificate validator from this library. It is configured to 
 * trust all issuers from the provided JKS truststore.
 * Additionally two CRL sources are registered: one remote and 
 * one local, using wildcard. CRLs are reloaded every hour and 
 * remote CRLs are cached in /tmp/crls (useful if subsequent 
 * download fails). Listener is registered which logs successful 
 * and erroneous updates of the trust material.
 * Finally a local credential from another JKS file is loaded, 
 * to be used as local side server's certificate and private key. 
 */
char [] keystorePassword = "somePasswd".toCharArray(), 
	ksPasswd = "passwd2".toCharArray(), 
	keyPasswd = "passwd3".toCharArray();
String serverKeyAlias = "someAlias";
List<String> crlSources = new ArrayList<String>();
Collections.addAll(crlSources, "http://some.crl.distr.point1/crl.pem", 
	"/etc/crls/*.crl");
StoreUpdateListener listener = new StoreUpdateListener() {
	public void loadingNotification(String location, String type, 
			Severity level,	Exception cause)
	{
		if (level != Severity.NOTIFICATION) {
			//log problem with loading 'type' data 
			//from 'location', details are usually in 
			//cause.
		} else {
			//log successful (re)loading
		}
	}
};
CRLParameters crlParams = new CRLParameters(crlSources, 3600000, 
	15000, "/tmp/crls");
OCSPParametes ocspParams = new OCSPParametes(OCSPCheckingMode.IF_AVAILABLE);
ValidatorParamsExt commonParams = new ValidatorParamsExt(
	new RevocationParametersExt(CrlCheckingMode.REQUIRE, 
		crlParams, ocspParams),
	ProxySupport.ALLOW, Collections.singletonList(listener));

KeystoreCertChainValidator v = new KeystoreCertChainValidator(
	"/my/truststore.jks", keystorePassword, "JKS", 1000, 
	commonParams);

X509Credential c = new KeystoreCredential("/my/keystore.jks", 
	ksPasswd, keyPasswd, serverKeyAlias, "JKS");
HostnameMismatchCallback2 hostnameMismatchCallback = new HostnameMismatchCallback2()
{
	@Override
	public void nameMismatch(X509Certificate peerCertificate, String hostName) throws CertificateException
	{
		// TODO Auto-generated method stub
		
	}
};
SSLServerSocketFactory sslSsf = new SocketFactoryCreator2(c, v, hostnameMismatchCallback).getServerSocketFactory();
		
ServerSocket sslSS = sslSsf.createServerSocket();

	}
	
	
	public void example3() throws Exception
	{
		InputStream inputStream = null;
		
X509Certificate someCertificate = CertificateUtils.loadCertificate(
	inputStream, Encoding.PEM);
X500Principal dn1 = someCertificate.getSubjectX500Principal();
String dn2 = "CN=Bob,O=Example,C=EX";
//correctly compares binary DN with a string one
boolean equal = X500NameUtils.equal(dn1, dn2); 

	}

}
