/*
 * eID Identity Provider Project.
 * Copyright (C) 2010 FedICT.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License version
 * 3.0 as published by the Free Software Foundation.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, see 
 * http://www.gnu.org/licenses/.
 */

package test.unit.be.fedict.eid.idp.protocol.saml2;

import be.fedict.eid.idp.common.saml2.Saml2Util;
import be.fedict.eid.idp.spi.Attribute;
import be.fedict.eid.idp.spi.IdentityProviderFlow;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.joda.time.DateTime;
import org.junit.BeforeClass;
import org.junit.Test;
import org.opensaml.saml2.core.Assertion;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.HashMap;
import java.util.UUID;

import static org.junit.Assert.assertEquals;

public class SAML2Test {

        private static final Log LOG = LogFactory
                .getLog(SAML2Test.class);

        @BeforeClass
        public static void before() {
                Security.addProvider(new BouncyCastleProvider());
        }

        @Test
        public void testAssertionSigning() throws Exception {

                // Setup
                DateTime notBefore = new DateTime();
                DateTime notAfter = notBefore.plusMonths(1);

                KeyPair rootKeyPair = generateKeyPair();
                X509Certificate rootCertificate = generateSelfSignedCertificate(
                        rootKeyPair, "CN=TestRoot", notBefore, notAfter);

                KeyPair endKeyPair = generateKeyPair();
                X509Certificate endCertificate = generateCertificate(
                        endKeyPair.getPublic(), "CN=Test", notBefore, notAfter,
                        rootCertificate, rootKeyPair.getPrivate());

                Certificate[] certChain = {endCertificate, rootCertificate};

                KeyStore.PrivateKeyEntry idpIdentity =
                        new KeyStore.PrivateKeyEntry(endKeyPair.getPrivate(),
                                certChain);

                // Operate: sign
                Assertion assertion = Saml2Util.getAssertion("test-issuer",
                        "test-in-response-to", "test-audience", new DateTime(),
                        IdentityProviderFlow.AUTHENTICATION,
                        UUID.randomUUID().toString(), new HashMap<String, Attribute>());
                Assertion signedAssertion = (Assertion) Saml2Util.sign(assertion,
                        idpIdentity);

                // Verify
                String result = Saml2Util.domToString(Saml2Util.marshall(signedAssertion), true);
                LOG.debug("DOM signed assertion: " + result);
                String result2 = Saml2Util.domToString(Saml2Util.marshall(assertion), true);
                LOG.debug("signed assertion: " + result2);
                assertEquals(result, result2);

                // Operate: validate
                Saml2Util.validateSignature(signedAssertion.getSignature());
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

                return generateCertificate(keyPair.getPublic(), subjectDn,
                        notBefore, notAfter, null, keyPair.getPrivate());
        }

        private X509Certificate generateCertificate(PublicKey subjectPublicKey,
                                                    String subjectDn,
                                                    DateTime notBefore,
                                                    DateTime notAfter,
                                                    X509Certificate issuerCertificate,
                                                    PrivateKey issuerPrivateKey)
                throws Exception {

                X509V3CertificateGenerator certificateGenerator = new X509V3CertificateGenerator();
                certificateGenerator.reset();
                certificateGenerator.setPublicKey(subjectPublicKey);
                certificateGenerator.setSignatureAlgorithm("SHA1WithRSAEncryption");
                certificateGenerator.setNotBefore(notBefore.toDate());
                certificateGenerator.setNotAfter(notAfter.toDate());

                X509Principal issuerDN;
                if (null != issuerCertificate) {
                        issuerDN = new X509Principal(issuerCertificate
                                .getSubjectX500Principal().toString());
                } else {
                        issuerDN = new X509Principal(subjectDn);
                }
                certificateGenerator.setIssuerDN(issuerDN);
                certificateGenerator.setSubjectDN(new X509Principal(subjectDn));
                certificateGenerator.setSerialNumber(new BigInteger(128,
                        new SecureRandom()));

                certificateGenerator.addExtension(
                        X509Extensions.SubjectKeyIdentifier, false,
                        createSubjectKeyId(subjectPublicKey));

                PublicKey issuerPublicKey;
                if (null != issuerCertificate) {
                        issuerPublicKey = issuerCertificate.getPublicKey();
                } else {
                        issuerPublicKey = subjectPublicKey;
                }
                certificateGenerator.addExtension(
                        X509Extensions.AuthorityKeyIdentifier, false,
                        createAuthorityKeyId(issuerPublicKey));

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
}