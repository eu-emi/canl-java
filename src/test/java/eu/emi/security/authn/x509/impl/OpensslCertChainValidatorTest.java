/*
 *     Copyright 2023 Deutsches Elektronen-Synchrotron (DESY)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *          http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package eu.emi.security.authn.x509.impl;

import static java.time.Duration.of;
import static java.time.temporal.ChronoUnit.DAYS;
import static java.time.temporal.ChronoUnit.HOURS;
import static java.time.temporal.ChronoUnit.MINUTES;
import static java.util.Arrays.asList;
import static java.util.Objects.requireNonNull;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.Collectors;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import eu.emi.security.authn.x509.CrlCheckingMode;
import eu.emi.security.authn.x509.NamespaceCheckingMode;
import eu.emi.security.authn.x509.OCSPCheckingMode;
import eu.emi.security.authn.x509.OCSPParametes;
import eu.emi.security.authn.x509.ProxySupport;
import eu.emi.security.authn.x509.RevocationParameters;
import eu.emi.security.authn.x509.ValidationResult;
import eu.emi.security.authn.x509.helpers.trust.OpensslTruststoreHelper;

/**
 * A set of unit-tests to verify correct behaviour of
 * OpensslCertChainValidator that follow the BDD style.
 */
public class OpensslCertChainValidatorTest
{
	private OpensslCertChainValidator validator;
	private Path trustStore;

	@Before
	public void setup() throws IOException {
		validator = null;
		trustStore = Paths.get("target/openssl-trust-stores/" +
				ThreadLocalRandom.current().nextLong(0, Long.MAX_VALUE));
		Files.createDirectories(trustStore);
	}

	@After
	public void tearDown() throws IOException {
		if (Files.exists(trustStore)) {
			Files.walk(trustStore)
			.sorted(Comparator.reverseOrder())
			.map(Path::toFile)
			.forEach(File::delete);
		}

		if (validator != null) {
			validator.dispose();
		}
	}

	@Test
	public void shouldValidateRootIssuedEEC() throws Exception {
		CA rootCA = given(aCertificateAuthority()
				.selfSigned()
				.withName("DC=org, DC=example, CN=root CA"));

		given(anOpensslTrustStore()
				.withNamespacesFiles()
				.withSigningPolicyFiles()
				.trustingCA(rootCA)
				.authorising("/DC=org/DC=example"));

		given(anOpensslCertChainValidator()
				.with(OCSPCheckingMode.IGNORE)
				.with(CrlCheckingMode.REQUIRE)
				.with(ProxySupport.ALLOW)
				.with(NamespaceCheckingMode.EUGRIDPMA_AND_GLOBUS_REQUIRE)
				.withUpdateInterval(of(2, MINUTES))
				.withLazyLoading());

		X509Certificate serviceCertificate = given(anEEC()
				.withSubject("DC=org, DC=example, CN=remote host")
				.signedBy(rootCA));

		ValidationResult result = whenValidating(serviceCertificate);

		assertThat(result.isValid(), is(equalTo(true)));
		assertThat(result.getErrors(), is(empty()));
		assertThat(result.getUnresolvedCriticalExtensions(), is(empty()));
	}

	@Test
	public void shouldValidateIntermediateCaIssuedEEC() throws Exception {
		CA rootCA = given(aCertificateAuthority()
				.selfSigned()
				.withName("DC=org, DC=example, CN=root CA"));
		CA interCA = given(aCertificateAuthority()
				.signedBy(rootCA)
				.withName("DC=org, DC=example, CN=intermediate CA 1"));

		given(anOpensslTrustStore()
				.withNamespacesFiles()
				.withSigningPolicyFiles()
				.trustingCA(rootCA)
				.authorising("/DC=org/DC=example")
				.andTrustingCA(interCA)
				.authorising("/DC=org/DC=example"));

		given(anOpensslCertChainValidator()
				.with(OCSPCheckingMode.IGNORE)
				.with(CrlCheckingMode.REQUIRE)
				.with(ProxySupport.ALLOW)
				.with(NamespaceCheckingMode.EUGRIDPMA_AND_GLOBUS_REQUIRE)
				.withUpdateInterval(of(2, MINUTES))
				.withLazyLoading());

		X509Certificate serviceCertificate = given(anEEC()
				.withSubject("DC=org, DC=example, CN=remote host")
				.signedBy(interCA));

		ValidationResult result = whenValidating(serviceCertificate);

		assertThat(result.isValid(), is(equalTo(true)));
		assertThat(result.getErrors(), is(empty()));
		assertThat(result.getUnresolvedCriticalExtensions(), is(empty()));
	}

	@Ignore("Demonstrates the problem describe in GitHub issue #116")
	@Test
	public void shouldIgnoreIrrelevantCAWithWrongSubject() throws Exception {
		CA root = given(aCertificateAuthority()
				.selfSigned()
				.withName("DC=org, DC=example, CN=first root"));
		CA inter1 = given(aCertificateAuthority()
				.signedBy(root)
				.withName("DC=org, DC=example, CN=first intermediate"));
		CA inter2 = given(aCertificateAuthority()
				.signedBy(root)
				.withName("DC=ch, DC=cern, CN=second intermediate"));

		given(anOpensslTrustStore()
				.withNamespacesFiles()
				.withSigningPolicyFiles()
				.trustingCA(root)
				.authorising("/DC=org/DC=example")
				.andTrustingCA(inter1)
				.authorising("/DC=org/DC=example"));

		given(anOpensslCertChainValidator()
				.with(OCSPCheckingMode.IGNORE)
				.with(CrlCheckingMode.REQUIRE)
				.with(ProxySupport.ALLOW)
				.with(NamespaceCheckingMode.EUGRIDPMA_AND_GLOBUS_REQUIRE)
				.withUpdateInterval(of(2, MINUTES))
				.withLazyLoading());

		X509Certificate serviceCertificate = given(anEEC()
				.withSubject("DC=org, DC=example, CN=remote host")
				.signedBy(inter1));

		ValidationResult result = whenValidating(
				root.getCertificate(),
				inter1.getCertificate(),
				inter2.getCertificate(),
				serviceCertificate);

		assertThat(result.isValid(), is(equalTo(true)));
		assertThat(result.getErrors(), is(empty()));
		assertThat(result.getUnresolvedCriticalExtensions(), is(empty()));
	}

	private ValidationResult whenValidating(X509Certificate... certificates) {
		return validator.validate(certificates);
	}

	private OpensslCertChainValidatorBuilder anOpensslCertChainValidator() {
		return new OpensslCertChainValidatorBuilder();
	}

	private CABuilder aCertificateAuthority() {
		return new CABuilder();
	}

	private CertificateBuilder anEEC() {
		return new CertificateBuilder().asEEC().ofLostCredental();
	}

	private OpensslTrustStoreBuilder anOpensslTrustStore() throws IOException {
		return new OpensslTrustStoreBuilder();
	}

	private void given(OpensslCertChainValidatorBuilder builder) {
		validator = builder.build();
	}

	private void given(OpensslTrustStoreBuilder.TrustBuilder builder) throws IOException {
		builder.and().build();
	}

	private CA given(CABuilder builder) throws OperatorCreationException, CertIOException, CertificateException {
		return builder.build();
	}

	private X509Certificate given(CertificateBuilder builder) throws OperatorCreationException, CertIOException, CertificateException {
		return builder.build();
	}

	/**
	 * Builder pattern class for creating and configuring an
	 * OpensslCertChainValidator instance.
	 */
	private class OpensslCertChainValidatorBuilder {
		private OCSPCheckingMode ocspMode;
		private CrlCheckingMode crlCheckingMode;
		private ProxySupport proxySupport;
		private NamespaceCheckingMode namespaceCheckingMode;
		private Duration updateInterval;
		private boolean isLazy;

		public OpensslCertChainValidatorBuilder with(OCSPCheckingMode mode) {
			ocspMode = requireNonNull(mode);
			return this;
		}

		public OpensslCertChainValidatorBuilder with(CrlCheckingMode mode) {
			crlCheckingMode = requireNonNull(mode);
			return this;
		}

		public OpensslCertChainValidatorBuilder with(ProxySupport mode) {
			proxySupport = requireNonNull(mode);
			return this;
		}

		public OpensslCertChainValidatorBuilder with(NamespaceCheckingMode mode) {
			namespaceCheckingMode = requireNonNull(mode);
			return this;
		}

		public OpensslCertChainValidatorBuilder withUpdateInterval(Duration interval) {
			updateInterval = requireNonNull(interval);
			return this;
		}

		public OpensslCertChainValidatorBuilder withLazyLoading() {
			this.isLazy = true;
			return this;
		}

		public OpensslCertChainValidator build() {
			assertThat(ocspMode, not(nullValue()));
			assertThat(crlCheckingMode, not(nullValue()));
			assertThat(proxySupport, not(nullValue()));
			assertThat(namespaceCheckingMode, not(nullValue()));
			assertThat(updateInterval, not(nullValue()));

			OCSPParametes ocspParameters = new OCSPParametes(ocspMode);
			RevocationParameters revocationParams =
					new RevocationParameters(crlCheckingMode, ocspParameters);
			ValidatorParams validatorParams = new ValidatorParams(revocationParams,
					proxySupport);

			return new OpensslCertChainValidator(trustStore.toString(), true,
					namespaceCheckingMode, updateInterval.toMillis(),
					validatorParams, isLazy);
		}
	}

	/**
	 * Builder pattern class for creating the OpenSSL trust store.
	 */
	private class OpensslTrustStoreBuilder {
		private final List<TrustBuilder> trusts = new ArrayList<>();
		private boolean writeNamespacesFiles;
		private boolean writeSigningPolicyFiles;

		public OpensslTrustStoreBuilder() throws IOException {
			Files.createDirectories(trustStore);
		}

		public OpensslTrustStoreBuilder withNamespacesFiles() {
			writeNamespacesFiles = true;
			return this;
		}

		public OpensslTrustStoreBuilder withSigningPolicyFiles() {
			writeSigningPolicyFiles = true;
			return this;
		}

		public TrustBuilder trustingCA(CA ca) {
			TrustBuilder trust = new TrustBuilder(ca, writeNamespacesFiles,
					writeSigningPolicyFiles);
			trusts.add(trust);
			return trust;
		}

		public void build() throws IOException {
			for (TrustBuilder tb : trusts) {
				tb.build();
			}
		}

		/**
		 * Builder pattern class for configuring trust of a specific CA.
		 */
		private class TrustBuilder {
			private final CA ca;
			private final String hash;
			private final List<String> authorisedNames = new ArrayList<>();
			private final boolean writeNamespacesFiles;
			private final boolean writeSigningPolicyFiles;

			private TrustBuilder(CA ca, boolean namespaces, boolean signingpolicy) {
				this.ca = ca;
				writeNamespacesFiles = namespaces;
				writeSigningPolicyFiles = signingpolicy;

				hash = OpensslTruststoreHelper.getOpenSSLCAHash(ca.getSubject(), true);
			}

			private void writeHashFile(String suffix, String contents) throws IOException {
				Path filePath = trustStore.resolve(hash + suffix);
				Files.write(filePath, contents.getBytes(StandardCharsets.UTF_8));
			}

			private TrustBuilder authorising(String... distinguishedNames) throws IOException {
				assertTrue("You need to enable either namespaces, signing_policy (or both) files",
						writeNamespacesFiles || writeSigningPolicyFiles);
				authorisedNames.addAll(asList(distinguishedNames));
				return this;
			}

			private void writeNamespaces() throws IOException {
				StringWriter stringWriter = new StringWriter();
				PrintWriter pw = new PrintWriter(stringWriter);
				for (String dn : authorisedNames) {
					pw.println("TO Issuer \"" + ca.getOldDn() + "\" \\");
					pw.println("  PERMIT Subject \"" + dn + "/.*\"");
					pw.println();
				}

				pw.flush();
				stringWriter.flush();

				writeHashFile(".namespaces", stringWriter.toString());
			}

			private void writeSigningPolicy() throws IOException {
				StringWriter stringWriter = new StringWriter();
				PrintWriter pw = new PrintWriter(stringWriter);
				pw.println("access_id_CA   X509    '" + ca.getOldDn() + "'");
				pw.println("pos_rights     globus  CA:sign");
				pw.println(authorisedNames.stream()
						.map(dn -> "\"" + dn + "/*\"")
						.collect(Collectors.joining(" ", "cond_subjects  globus  '", "'")));
				pw.flush();
				stringWriter.flush();
				writeHashFile(".signing_policy", stringWriter.toString());
			}

			private OpensslTrustStoreBuilder and() {
				return OpensslTrustStoreBuilder.this;
			}

			private TrustBuilder andTrustingCA(CA ca) throws IOException {
				return and().trustingCA(ca);
			}

			private void build() throws IOException {
				writeHashFile(".0", ca.buildPemCertificate());
				writeHashFile(".r0", ca.buildPemCrl());

				if (writeNamespacesFiles) {
					writeNamespaces();
				}

				if (writeSigningPolicyFiles) {
					writeSigningPolicy();
				}
			}
		}
	}

	/**
	 * A class that represents a certificate authority.  The CA may be either a
	 * root CA or intermediate CA.
	 */
	private static class CA {
		private final X509Certificate certificate;
		private final PrivateKey privateKey;

		public CA(X509Certificate certificate, PrivateKey privateKey) {
			this.certificate = requireNonNull(certificate);
			this.privateKey = requireNonNull(privateKey);
		}

		public X509Certificate getCertificate() {
			return certificate;
		}

		private String pemEncode(Object input) {
			try {
				StringWriter stringWriter = new StringWriter();
				JcaPEMWriter writer = new JcaPEMWriter(stringWriter);
				writer.writeObject(input);
				writer.flush();
				return stringWriter.toString();
			} catch (IOException e) {
				throw new RuntimeException("Unexpected IOException " + e, e);
			}
		}

		public String buildPemCertificate() {
			return pemEncode(certificate);
		}

		public String buildPemCrl() {
			Instant validFrom = Instant.now().minus(10, MINUTES);
			X509v2CRLBuilder builder = new JcaX509v2CRLBuilder(certificate, Date.from(validFrom));
			builder.setNextUpdate(Date.from(validFrom.plus(7, DAYS)));
			try {
				ContentSigner signer = new JcaContentSignerBuilder("SHA256WITHRSAENCRYPTION")
						.setProvider("BC")
						.build(privateKey);
				X509CRL crl = new JcaX509CRLConverter().setProvider("BC").getCRL(builder.build(signer));
				return pemEncode(crl);
			} catch (CRLException | OperatorCreationException e) {
				throw new RuntimeException("Unexpected exception " + e, e);
			}
		}

		public void sign(CertificateBuilder builder) {
			builder.withIssuer(getDn());
			builder.signedBy(privateKey);
		}

		public X500Principal getSubject() {
			return certificate.getSubjectX500Principal();
		}

		public String getDn() {
			return X500Name.getInstance(getSubject().getEncoded()).toString();
		}

		public String getOldDn() {
			String rfc2253 = getSubject().getName();
			return OpensslNameUtils.convertFromRfc2253(rfc2253, true);
		}
	}

	/**
	 * A builder pattern class for creating a new CA.
	 */
	private static class CABuilder {
		private String name;
		private Optional<CA> signedBy = Optional.empty();
		private final PublicKey publicKey;
		private final PrivateKey privateKey;

		public CABuilder() {
			KeyPair kp = buildKeyPair();
			publicKey = kp.getPublic();
			privateKey = kp.getPrivate();
		}

		public CABuilder withName(String name) {
			this.name = name;
			return this;
		}

		public CABuilder selfSigned() {
			signedBy = Optional.empty();
			return this;
		}

		public CABuilder signedBy(CA ca) {
			signedBy = Optional.of(ca);
			return this;
		}

		private KeyPair buildKeyPair() {
			KeyPairGenerator keyGen;
			try {
				keyGen = KeyPairGenerator.getInstance("RSA");
			} catch (NoSuchAlgorithmException e) {
				throw new RuntimeException("RSA not supported: " + e.getMessage(), e);
			}
			keyGen.initialize(2048);
			return keyGen.generateKeyPair();
		}

		private X509Certificate buildCertificate() throws OperatorCreationException, CertIOException, CertificateException {
			CertificateBuilder certBuilder = new CertificateBuilder()
					.withPublicKey(publicKey)
					.withSubject(name)
					.asCA();
			CertificateBuilder certBuilderWithSigner = signedBy
					.map(ca -> certBuilder.signedBy(ca))
					.orElseGet(() -> certBuilder.withIssuer(name).signedBy(privateKey));
			X509Certificate certificate = certBuilderWithSigner.build();
			return certificate;
		}

		public CA build() throws OperatorCreationException, OperatorCreationException, CertIOException, CertificateException {
			assertThat(name, not(nullValue()));

			X509Certificate certificate = buildCertificate();

			return new CA(certificate, privateKey);
		}
	}

	/**
	 * A builder pattern class for creating a certificate.  It can do this from
	 * either an existing public key or by generating a fresh public/private
	 * key-pair and discarding the private key.
	 */
	private static class CertificateBuilder {
		private PrivateKey signingKey;
		private PublicKey publicKey;
		private X500Name subject;
		private X500Name issuer;
		private Instant notBefore = Instant.now().minus(2, HOURS);
		private Instant notAfter = Instant.now().plus(2, HOURS);
		private BigInteger serial = new BigInteger(Long.toString(Instant.now().getEpochSecond()));
		private String algorithm = "SHA256WithRSA";
		private boolean isCA;

		public CertificateBuilder signedBy(CA ca) {
			ca.sign(this);
			return this;
		}

		public CertificateBuilder signedBy(PrivateKey key) {
			signingKey = key;
			return this;
		}

		public CertificateBuilder withSubject(String dn) {
			this.subject = new X500Name(dn);
			return this;
		}

		public CertificateBuilder withIssuer(String dn) {
			try {
				X500Principal p = X500NameUtils.getX500Principal(dn);
				this.issuer = new X500Name(p.getName());
				return this;
			} catch (IOException e) {
				throw new RuntimeException(e.toString(), e);
			}
		}

		public CertificateBuilder asCA() {
			isCA = true;
			return this;
		}

		public CertificateBuilder asEEC() {
			isCA = false;
			return this;
		}

		public CertificateBuilder withPublicKey(PublicKey key) {
			publicKey = requireNonNull(key);
			return this;
		}

		public CertificateBuilder ofLostCredental() {
			KeyPairGenerator keyGen;
			try {
				keyGen = KeyPairGenerator.getInstance("RSA");
			} catch (NoSuchAlgorithmException e) {
				throw new RuntimeException("RSA not supported: " + e.getMessage(), e);
			}
			keyGen.initialize(2048);
			KeyPair kp = keyGen.generateKeyPair();
			publicKey = kp.getPublic();
			return this; // Whoopsie, we just lost the private key.
		}

		public X509Certificate build() throws OperatorCreationException,
		CertIOException, CertificateException {
			assertThat(publicKey, not(nullValue()));
			assertThat(signingKey, not(nullValue()));
			assertThat(subject, not(nullValue()));
			assertThat(issuer, not(nullValue()));

			ContentSigner contentSigner = new JcaContentSignerBuilder(algorithm).build(signingKey);
			JcaX509v3CertificateBuilder certBuilder =
					new JcaX509v3CertificateBuilder(issuer, serial,
							Date.from(notBefore), Date.from(notAfter), subject,
							publicKey);
			BasicConstraints basicConstraints = new BasicConstraints(isCA);
			certBuilder.addExtension(new ASN1ObjectIdentifier("2.5.29.19"), true,
					basicConstraints);
			X509CertificateHolder holder = certBuilder.build(contentSigner);
			return new JcaX509CertificateConverter().setProvider("BC")
					.getCertificate(holder);
		}
	}
}
