/**
 * Helper classes included (mostly copied) from the BouncyCastle 1.52 library
 * and further updated.
 * This was done to fix errors present in BouncyCastle and to provide a decent error reporting.
 * Hopefully this package will be removed in future.
 * <p>
 * Warning: this package contains internal implementation of the library. It is not
 * guaranteed that API of the classes from this package will not change in future releases.
 * <p>
 * The code here is divided in two parts: classes copied from BC and minimally updated and 
 * custom extensions using those classes.
 * Custom classes are placed in this package as original BC classes has package access restriction and we 
 * fight to minimize changes. Custom classes are all ending with Canl and the class 
 * {@link eu.emi.security.authn.x509.helpers.pkipath.bc.FixedBCPKIXCertPathReviewer}.
 * <p>
 * Modifications in copied BC classes include: change of access restrictions and imports; use of 
 * {@link eu.emi.security.authn.x509.helpers.pkipath.bc.PKIXCRLStoreSelectorCanl} instead of the original selector.  
 *   
 */
package eu.emi.security.authn.x509.helpers.pkipath.bc;

