package be.fedict.eid.idp.sp.saml2;

import be.fedict.eid.idp.sp.protocol.saml2.spi.AuthenticationRequestService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.joda.time.DateTime;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Map;

public class AuthenticationRequestServiceBean implements AuthenticationRequestService, Serializable {

        private static final Log LOG = LogFactory.getLog(AuthenticationRequestServiceBean.class);

        private String endpoint;

        @Override
        public String getIdPDestination() {

                LOG.debug("get IdP destionation: " + endpoint);
                return endpoint;
        }

        @Override
        public String getRelayState(Map<String, String[]> parameterMap) {
                return null;
        }

        @Override
        public KeyStore.PrivateKeyEntry getSPIdentity() {

                LOG.debug("get SP Identity");
                try {
                        KeyPair keyPair = generateKeyPair();
                        DateTime notBefore = new DateTime();
                        DateTime notAfter = notBefore.plusMonths(1);
                        X509Certificate certificate = generateSelfSignedCertificate(keyPair,
                                "CN=Test", notBefore, notAfter);

                        return new KeyStore.PrivateKeyEntry(keyPair.getPrivate(),
                                new java.security.cert.Certificate[]{certificate});
                } catch (Exception e) {
                        LOG.error(e);
                        return null;
                }
        }

        private KeyPair generateKeyPair() throws Exception {
                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
                SecureRandom random = new SecureRandom();
                keyPairGenerator.initialize(new RSAKeyGenParameterSpec(1024,
                        RSAKeyGenParameterSpec.F4), random);
                return keyPairGenerator.generateKeyPair();
        }

        private SubjectKeyIdentifier createSubjectKeyId(PublicKey publicKey)
                throws IOException {
                ByteArrayInputStream bais = new ByteArrayInputStream(publicKey
                        .getEncoded());
                SubjectPublicKeyInfo info = new SubjectPublicKeyInfo(
                        (ASN1Sequence) new ASN1InputStream(bais).readObject());
                return new SubjectKeyIdentifier(info);
        }

        private AuthorityKeyIdentifier createAuthorityKeyId(PublicKey publicKey)
                throws IOException {

                ByteArrayInputStream bais = new ByteArrayInputStream(publicKey
                        .getEncoded());
                SubjectPublicKeyInfo info = new SubjectPublicKeyInfo(
                        (ASN1Sequence) new ASN1InputStream(bais).readObject());

                return new AuthorityKeyIdentifier(info);
        }

        private X509Certificate generateSelfSignedCertificate(KeyPair keyPair,
                                                              String subjectDn, DateTime notBefore, DateTime notAfter)
                throws Exception {
                PublicKey subjectPublicKey = keyPair.getPublic();
                PrivateKey issuerPrivateKey = keyPair.getPrivate();
                String signatureAlgorithm = "SHA1WithRSAEncryption";
                X509V3CertificateGenerator certificateGenerator = new X509V3CertificateGenerator();
                certificateGenerator.reset();
                certificateGenerator.setPublicKey(subjectPublicKey);
                certificateGenerator.setSignatureAlgorithm(signatureAlgorithm);
                certificateGenerator.setNotBefore(notBefore.toDate());
                certificateGenerator.setNotAfter(notAfter.toDate());
                X509Principal issuerDN = new X509Principal(subjectDn);
                certificateGenerator.setIssuerDN(issuerDN);
                certificateGenerator.setSubjectDN(new X509Principal(subjectDn));
                certificateGenerator.setSerialNumber(new BigInteger(128,
                        new SecureRandom()));

                certificateGenerator.addExtension(X509Extensions.SubjectKeyIdentifier,
                        false, createSubjectKeyId(subjectPublicKey));
                PublicKey issuerPublicKey;
                issuerPublicKey = subjectPublicKey;
                certificateGenerator.addExtension(
                        X509Extensions.AuthorityKeyIdentifier, false,
                        createAuthorityKeyId(issuerPublicKey));

                certificateGenerator.addExtension(X509Extensions.BasicConstraints,
                        false, new BasicConstraints(true));

                X509Certificate certificate;
                certificate = certificateGenerator.generate(issuerPrivateKey);

                /*
                * Next certificate factory trick is needed to make sure that the
                * certificate delivered to the caller is provided by the default
                * security provider instead of BouncyCastle. If we don't do this trick
                * we might run into trouble when trying to use the CertPath validator.
                */
                CertificateFactory certificateFactory = CertificateFactory
                        .getInstance("X.509");
                certificate = (X509Certificate) certificateFactory
                        .generateCertificate(new ByteArrayInputStream(certificate
                                .getEncoded()));
                return certificate;
        }

        public String getEndpoint() {
                return endpoint;
        }

        public void setEndpoint(String endpoint) {
                this.endpoint = endpoint;
        }
}
