import eu.emi.security.authn.x509.CrlCheckingMode;
import eu.emi.security.authn.x509.NamespaceCheckingMode;
import eu.emi.security.authn.x509.OCSPCheckingMode;
import eu.emi.security.authn.x509.OCSPParametes;
import eu.emi.security.authn.x509.ProxySupport;
import eu.emi.security.authn.x509.RevocationParameters;
import eu.emi.security.authn.x509.ValidationError;
import eu.emi.security.authn.x509.ValidationResult;
import eu.emi.security.authn.x509.X509CertChainValidator;
import eu.emi.security.authn.x509.impl.OpensslCertChainValidator;
import eu.emi.security.authn.x509.impl.PEMCredential;
import eu.emi.security.authn.x509.impl.ValidatorParams;

import java.security.cert.X509Certificate;

/**
 * Validates that a server private key and certificate are:
 *   1. Matching (key pair is consistent)
 *   2. Trusted (chain validates against a given truststore)
 *
 * Usage:
 *   java ServerKeyPairValidator \
 *        /path/to/server.key \
 *        /path/to/server.crt \
 *        /path/to/custom/certifificates
 */
public class ServerKeyPairValidator {

    public static void main(String[] args) throws Exception {

        if (args.length < 2) {
            System.err.println("Usage: ServerKeyPairValidator <keyPath> <certPath> [caDir]");
            System.exit(1);
        }

        String keyPath  = args[0];
        String certPath = args[1];
        String caDir    = args.length >= 3 ? args[2] : "/etc/grid-security/certificates";

        // 1. Load credential — also verifies key matches certificate internally
        PEMCredential credential;
        try {
            credential = new PEMCredential(keyPath, certPath, (char[]) null);
        } catch (Exception e) {
            System.out.println("FAILED: Cannot load key/certificate pair.");
            System.out.println("  Reason: " + e.getMessage());
            System.exit(2);
            return;
        }

        X509Certificate[] chain = credential.getCertificateChain();
        System.out.println("Loaded certificate for: " + credential.getSubjectName());
        System.out.println("Chain length: " + chain.length);

        long trustAnchorRefreshInterval = 3_600_000;

        NamespaceCheckingMode namespaceMode =
            NamespaceCheckingMode.valueOf("IGNORE");
        CrlCheckingMode crlCheckingMode =
            CrlCheckingMode.valueOf("REQUIRE");
        OCSPCheckingMode ocspCheckingMode =
            OCSPCheckingMode.valueOf("REQUIRE");
        ValidatorParams validatorParams =
            new ValidatorParams(new RevocationParameters(crlCheckingMode,
                                                         new OCSPParametes(ocspCheckingMode)),
                                ProxySupport.ALLOW);
        X509CertChainValidator validator = new OpensslCertChainValidator(caDir,
                                                                         false,
                                                                         namespaceMode,
                                                                         trustAnchorRefreshInterval,
                                                                         validatorParams,
                                                                         false);


        // 3. Validate certificate chain against truststore
        ValidationResult result = validator.validate(chain);

        if (result.isValid()) {
            System.out.println("SUCCESS: Key/certificate pair is valid and trusted.");
        } else {
            System.out.println("FAILED: Certificate validation errors:");
            for (ValidationError error : result.getErrors()) {
                System.out.println("  [" + error.getErrorCode() + "] " + error.getMessage());
            }
            System.exit(3);
        }

        ((OpensslCertChainValidator) validator).dispose();
    }
}
