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

package be.fedict.eid.idp.common.saml2;

import be.fedict.eid.applet.service.Address;
import be.fedict.eid.applet.service.Identity;
import be.fedict.eid.idp.common.AttributeConstants;
import be.fedict.eid.idp.common.SamlAuthenticationPolicy;
import be.fedict.eid.idp.spi.IdentityProviderFlow;
import be.fedict.eid.idp.spi.IdpUtil;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.saml2.core.*;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.ws.wstrust.*;
import org.opensaml.ws.wstrust.impl.*;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.schema.XSBase64Binary;
import org.opensaml.xml.schema.XSDateTime;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.BasicCredential;
import org.opensaml.xml.security.keyinfo.KeyInfoHelper;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.*;
import org.opensaml.xml.signature.impl.SignatureBuilder;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.validation.ValidationException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.xml.namespace.QName;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.IOException;
import java.io.OutputStream;
import java.io.StringWriter;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.GregorianCalendar;
import java.util.LinkedList;
import java.util.List;
import java.util.UUID;

/**
 * Utility class for SAML v2.0
 */
public abstract class Saml2Util {

        static {
                /*
                * Next is because Sun loves to endorse crippled versions of Xerces.
                */
                System.setProperty("javax.xml.validation.SchemaFactory:http://www.w3.org/2001/XMLSchema",
                        "org.apache.xerces.jaxp.validation.XMLSchemaFactory");
                try {
                        DefaultBootstrap.bootstrap();

                        // register WS-Trust elements needed in WS-Federation
                        Configuration.registerObjectProvider(
                                RequestSecurityTokenResponseCollection.ELEMENT_NAME,
                                new RequestSecurityTokenResponseCollectionBuilder(),
                                new RequestSecurityTokenResponseCollectionMarshaller(),
                                new RequestSecurityTokenResponseCollectionUnmarshaller());

                        Configuration.registerObjectProvider(
                                RequestSecurityTokenResponse.ELEMENT_NAME,
                                new RequestSecurityTokenResponseBuilder(),
                                new RequestSecurityTokenResponseMarshaller(),
                                new RequestSecurityTokenResponseUnmarshaller());

                        Configuration.registerObjectProvider(
                                TokenType.ELEMENT_NAME,
                                new TokenTypeBuilder(),
                                new TokenTypeMarshaller(),
                                new TokenTypeUnmarshaller());

                        Configuration.registerObjectProvider(
                                RequestType.ELEMENT_NAME,
                                new RequestTypeBuilder(),
                                new RequestTypeMarshaller(),
                                new RequestTypeUnmarshaller());

                        Configuration.registerObjectProvider(
                                KeyType.ELEMENT_NAME,
                                new KeyTypeBuilder(),
                                new KeyTypeMarshaller(),
                                new KeyTypeUnmarshaller());

                        Configuration.registerObjectProvider(
                                RequestedSecurityToken.ELEMENT_NAME,
                                new RequestedSecurityTokenBuilder(),
                                new RequestedSecurityTokenMarshaller(),
                                new RequestedSecurityTokenUnmarshaller());

                } catch (ConfigurationException e) {
                        throw new RuntimeException("could not bootstrap the OpenSAML2 library", e);
                }
        }

        public static Assertion getAssertion(String inResponseTo,
                                             String audienceUri,
                                             DateTime issueInstant,
                                             IdentityProviderFlow authenticationFlow,
                                             String userId,
                                             String givenName, String surName,
                                             Identity identity,
                                             Address address,
                                             byte[] photo) {

                Assertion assertion = buildXMLObject(Assertion.class,
                        Assertion.DEFAULT_ELEMENT_NAME);
                assertion.setVersion(SAMLVersion.VERSION_20);
                String assertionId = "assertion-" + UUID.randomUUID().toString();
                assertion.setID(assertionId);
                assertion.setIssueInstant(issueInstant);

                Issuer issuer = buildXMLObject(Issuer.class, Issuer.DEFAULT_ELEMENT_NAME);
                assertion.setIssuer(issuer);
                issuer.setValue("http://www.e-contract.be/"); // TODO

                Conditions conditions =
                        buildXMLObject(Conditions.class, Conditions.DEFAULT_ELEMENT_NAME);
                assertion.setConditions(conditions);
                DateTime notBefore = issueInstant;
                DateTime notAfter = issueInstant.plusMinutes(5); // TODO: configurable
                conditions.setNotBefore(notBefore);
                conditions.setNotOnOrAfter(notAfter);
                List<AudienceRestriction> audienceRestrictionList = conditions
                        .getAudienceRestrictions();
                AudienceRestriction audienceRestriction =
                        buildXMLObject(AudienceRestriction.class,
                                AudienceRestriction.DEFAULT_ELEMENT_NAME);
                audienceRestrictionList.add(audienceRestriction);
                List<Audience> audiences = audienceRestriction.getAudiences();
                Audience audience = buildXMLObject(Audience.class,
                        Audience.DEFAULT_ELEMENT_NAME);
                audiences.add(audience);
                audience.setAudienceURI(audienceUri);

                Subject subject = buildXMLObject(Subject.class,
                        Subject.DEFAULT_ELEMENT_NAME);
                assertion.setSubject(subject);
                NameID nameId = buildXMLObject(NameID.class, NameID.DEFAULT_ELEMENT_NAME);
                subject.setNameID(nameId);
                nameId.setValue(userId);
                List<SubjectConfirmation> subjectConfirmations = subject
                        .getSubjectConfirmations();
                SubjectConfirmation subjectConfirmation =
                        buildXMLObject(SubjectConfirmation.class,
                                SubjectConfirmation.DEFAULT_ELEMENT_NAME);
                subjectConfirmations.add(subjectConfirmation);
                subjectConfirmation.setMethod("urn:oasis:names:tc:SAML:2.0:cm:bearer");
                if (null != inResponseTo) {
                        SubjectConfirmationData subjectConfirmationData =
                                buildXMLObject(SubjectConfirmationData.class,
                                        SubjectConfirmationData.DEFAULT_ELEMENT_NAME);
                        subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);
                        subjectConfirmationData.setRecipient(audienceUri);
                        subjectConfirmationData.setInResponseTo(inResponseTo);
                        subjectConfirmationData.setNotBefore(notBefore);
                        subjectConfirmationData.setNotOnOrAfter(notAfter);
                }

                List<AuthnStatement> authnStatements = assertion.getAuthnStatements();
                AuthnStatement authnStatement =
                        buildXMLObject(AuthnStatement.class, AuthnStatement.DEFAULT_ELEMENT_NAME);
                authnStatements.add(authnStatement);
                authnStatement.setAuthnInstant(issueInstant);
                AuthnContext authnContext =
                        buildXMLObject(AuthnContext.class, AuthnContext.DEFAULT_ELEMENT_NAME);
                authnStatement.setAuthnContext(authnContext);

                AuthnContextClassRef authnContextClassRef =
                        buildXMLObject(AuthnContextClassRef.class,
                                AuthnContextClassRef.DEFAULT_ELEMENT_NAME);

                switch (authenticationFlow) {

                        case IDENTIFICATION:
                                authnContextClassRef.setAuthnContextClassRef(
                                        SamlAuthenticationPolicy.IDENTIFICATION.getUri());
                                break;
                        case AUTHENTICATION:
                                authnContextClassRef.setAuthnContextClassRef(
                                        SamlAuthenticationPolicy.AUTHENTICATION.getUri());
                                break;
                        case AUTHENTICATION_WITH_IDENTIFICATION:
                                authnContextClassRef.setAuthnContextClassRef(
                                        SamlAuthenticationPolicy.AUTHENTICATION_WITH_IDENTIFICATION.getUri());
                                break;
                }

                authnContext.setAuthnContextClassRef(authnContextClassRef);

                List<AttributeStatement> attributeStatements = assertion
                        .getAttributeStatements();
                AttributeStatement attributeStatement =
                        buildXMLObject(AttributeStatement.class,
                                AttributeStatement.DEFAULT_ELEMENT_NAME);
                attributeStatements.add(attributeStatement);

                addAttribute(AttributeConstants.LAST_NAME_CLAIM_TYPE_URI,
                        surName, attributeStatement);
                addAttribute(AttributeConstants.FIRST_NAME_CLAIM_TYPE_URI, givenName,
                        attributeStatement);
                addAttribute(AttributeConstants.NAME_CLAIM_TYPE_URI,
                        givenName + " " + surName, attributeStatement);
                addAttribute(AttributeConstants.PPID_CLAIM_TYPE_URI, userId,
                        attributeStatement);

                if (null != address) {

                        addAttribute(AttributeConstants.STREET_ADDRESS_CLAIM_TYPE_URI,
                                address.getStreetAndNumber(), attributeStatement);
                        addAttribute(AttributeConstants.LOCALITY_CLAIM_TYPE_URI,
                                address.getMunicipality(), attributeStatement);
                        addAttribute(AttributeConstants.POSTAL_CODE_CLAIM_TYPE_URI,
                                address.getZip(), attributeStatement);
                }

                if (null != identity) {

                        addAttribute(AttributeConstants.GENDER_CLAIM_TYPE_URI,
                                IdpUtil.getGenderValue(identity), attributeStatement);
                        addAttribute(AttributeConstants.DATE_OF_BIRTH_CLAIM_TYPE_URI,
                                identity.getDateOfBirth(), attributeStatement);
                        addAttribute(AttributeConstants.NATIONALITY_CLAIM_TYPE_URI,
                                identity.getNationality(), attributeStatement);
                        addAttribute(AttributeConstants.PLACE_OF_BIRTH_CLAIM_TYPE_URI,
                                identity.getPlaceOfBirth(), attributeStatement);
                }

                if (null != photo) {

                        addAttribute(AttributeConstants.PHOTO_CLAIM_TYPE_URI,
                                photo, attributeStatement);
                }

                return assertion;
        }

        @SuppressWarnings("unchecked")
        private static void addAttribute(String attributeName, String attributeValue,
                                         AttributeStatement attributeStatement) {

                List<Attribute> attributes = attributeStatement.getAttributes();

                Attribute attribute = buildXMLObject(Attribute.class, Attribute.DEFAULT_ELEMENT_NAME);
                attribute.setName(attributeName);
                attributes.add(attribute);

                XMLObjectBuilder<XSString> builder =
                        Configuration.getBuilderFactory().getBuilder(XSString.TYPE_NAME);
                XSString xmlAttributeValue = builder.buildObject(
                        AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
                xmlAttributeValue.setValue(attributeValue);
                attribute.getAttributeValues().add(xmlAttributeValue);
        }

        @SuppressWarnings("unchecked")
        private static void addAttribute(String attributeName,
                                         GregorianCalendar attributeValue,
                                         AttributeStatement attributeStatement) {

                List<Attribute> attributes = attributeStatement.getAttributes();

                Attribute attribute = buildXMLObject(Attribute.class, Attribute.DEFAULT_ELEMENT_NAME);
                attribute.setName(attributeName);
                attributes.add(attribute);

                XMLObjectBuilder<XSDateTime> builder =
                        Configuration.getBuilderFactory().getBuilder(XSDateTime.TYPE_NAME);
                XSDateTime xmlAttributeValue = builder.buildObject(
                        AttributeValue.DEFAULT_ELEMENT_NAME, XSDateTime.TYPE_NAME);
                xmlAttributeValue.setValue(new DateTime(attributeValue.getTime()));
                attribute.getAttributeValues().add(xmlAttributeValue);
        }

        @SuppressWarnings("unchecked")
        private static void addAttribute(String attributeName, byte[] attributeValue,
                                         AttributeStatement attributeStatement) {

                List<Attribute> attributes = attributeStatement.getAttributes();

                Attribute attribute = buildXMLObject(Attribute.class, Attribute.DEFAULT_ELEMENT_NAME);
                attribute.setName(attributeName);
                attributes.add(attribute);

                XMLObjectBuilder<XSBase64Binary> builder =
                        Configuration.getBuilderFactory().getBuilder(XSBase64Binary.TYPE_NAME);
                XSBase64Binary xmlAttributeValue = builder.buildObject(
                        AttributeValue.DEFAULT_ELEMENT_NAME, XSBase64Binary.TYPE_NAME);
                xmlAttributeValue.setValue(Base64.encodeBytes(attributeValue));
                attribute.getAttributeValues().add(xmlAttributeValue);
        }

        @SuppressWarnings("unused")
        public static <T extends XMLObject> T buildXMLObject(Class<T> clazz, QName objectQName) {

                @SuppressWarnings("unchecked")
                XMLObjectBuilder<T> builder = Configuration.getBuilderFactory().getBuilder(objectQName);
                if (builder == null) {
                        throw new RuntimeException("Unable to retrieve builder for object QName " + objectQName);
                }

                return builder.buildObject(objectQName);
        }

        public static Element signAsElement(XMLObject xmlObject,
                                            SignableSAMLObject signableSAMLObject,
                                            X509Certificate certificate,
                                            PrivateKey privateKey) {

                XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
                SignatureBuilder signatureBuilder = (SignatureBuilder) builderFactory.getBuilder(Signature.DEFAULT_ELEMENT_NAME);
                Signature signature = signatureBuilder.buildObject();
                signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

                String algorithm = privateKey.getAlgorithm();
                if ("RSA".equals(algorithm)) {
                        signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA);
                } else if ("DSA".equals(algorithm)) {
                        signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_DSA);
                }

                // add certificate as keyinfo
                KeyInfo keyInfo = buildXMLObject(KeyInfo.class, KeyInfo.DEFAULT_ELEMENT_NAME);
                try {
                        KeyInfoHelper.addCertificate(keyInfo, certificate);
                } catch (CertificateEncodingException e) {
                        throw new RuntimeException("opensaml2 certificate encoding error: " + e.getMessage(), e);
                }
                signature.setKeyInfo(keyInfo);

                BasicCredential signingCredential =
                        SecurityHelper.getSimpleCredential(certificate, privateKey);
                signature.setSigningCredential(signingCredential);
                signableSAMLObject.setSignature(signature);

                // Marshall so it has an XML representation.
                Element xmlElement = marshall(xmlObject);

                // Sign after marshaling so we can add a signature to the XML representation.
                try {
                        Signer.signObject(signature);
                } catch (SignatureException e) {
                        throw new RuntimeException("opensaml2 signing error: " + e.getMessage(), e);
                }
                return xmlElement;
        }

        public static SignableSAMLObject sign(SignableSAMLObject signableSAMLObject,
                                              KeyStore.PrivateKeyEntry privateKeyEntry) {

                XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
                SignatureBuilder signatureBuilder = (SignatureBuilder) builderFactory.getBuilder(Signature.DEFAULT_ELEMENT_NAME);
                Signature signature = signatureBuilder.buildObject();
                signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

                String algorithm = privateKeyEntry.getPrivateKey().getAlgorithm();
                if ("RSA".equals(algorithm)) {
                        signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA);
                } else if ("DSA".equals(algorithm)) {
                        signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_DSA);
                }

                List<X509Certificate> certificateChain = new LinkedList<X509Certificate>();
                for (java.security.cert.Certificate certificate : privateKeyEntry.getCertificateChain()) {
                        certificateChain.add((X509Certificate) certificate);
                }

                // add certificate chain as keyinfo
                KeyInfo keyInfo = buildXMLObject(KeyInfo.class, KeyInfo.DEFAULT_ELEMENT_NAME);
                try {
                        for (X509Certificate certificate : certificateChain) {
                                KeyInfoHelper.addCertificate(keyInfo, certificate);
                        }
                } catch (CertificateEncodingException e) {
                        throw new RuntimeException("opensaml2 certificate encoding error: " + e.getMessage(), e);
                }
                signature.setKeyInfo(keyInfo);

                BasicX509Credential signingCredential = new BasicX509Credential();
                signingCredential.setPrivateKey(privateKeyEntry.getPrivateKey());
                signingCredential.setEntityCertificateChain(certificateChain);
                signature.setSigningCredential(signingCredential);
                signableSAMLObject.setSignature(signature);

                // Marshall so it has an XML representation.
                marshall(signableSAMLObject);

                // Sign after marshaling so we can add a signature to the XML representation.
                try {
                        Signer.signObject(signature);
                } catch (SignatureException e) {
                        throw new RuntimeException("opensaml2 signing error: " + e.getMessage(), e);
                }
                return signableSAMLObject;
        }

        public static List<X509Certificate> validateSignature(Signature signature)
                throws CertificateException, ValidationException {

                List<X509Certificate> certChain =
                        KeyInfoHelper.getCertificates(signature.getKeyInfo());

                SAMLSignatureProfileValidator pv =
                        new SAMLSignatureProfileValidator();
                pv.validate(signature);
                BasicX509Credential credential = new BasicX509Credential();
                credential.setPublicKey(getEndCertificate(certChain).getPublicKey());
                SignatureValidator sigValidator = new SignatureValidator(credential);
                sigValidator.validate(signature);

                return certChain;
        }

        public static X509Certificate getEndCertificate(List<X509Certificate> certChain) {

                if (certChain.size() == 1) {
                        return certChain.get(0);
                }

                if (isSelfSigned(certChain.get(0))) {
                        return certChain.get(certChain.size() - 1);
                } else {
                        return certChain.get(0);
                }

        }

        private static boolean isSelfSigned(X509Certificate certificate) {

                return certificate.getIssuerX500Principal().equals(
                        certificate.getSubjectX500Principal());
        }


        public static Element marshall(XMLObject xmlObject) {

                MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();
                Marshaller marshaller = marshallerFactory.getMarshaller(xmlObject);

                try {
                        return marshaller.marshall(xmlObject);
                } catch (MarshallingException e) {
                        throw new RuntimeException("opensaml2 marshalling error: " + e.getMessage(), e);
                }
        }

        public static void writeDocument(Document document,
                                         OutputStream documentOutputStream)
                throws TransformerFactoryConfigurationError, TransformerException,
                IOException {
                Result result = new StreamResult(documentOutputStream);
                Transformer xformer = TransformerFactory.newInstance().newTransformer();
                Source source = new DOMSource(document);
                xformer.transform(source, result);
        }


        public static String domToString(Node domNode, boolean indent) {

                try {
                        Source source = new DOMSource(domNode);
                        StringWriter stringWriter = new StringWriter();
                        Result result = new StreamResult(stringWriter);

                        TransformerFactory transformerFactory = TransformerFactory.newInstance();
                        Transformer transformer = transformerFactory.newTransformer();

                        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
                        transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "4");
                        transformer.setOutputProperty(OutputKeys.INDENT, indent ? "yes" : "no");
                        transformer.transform(source, result);

                        return stringWriter.toString();
                } catch (TransformerException e) {
                        throw new RuntimeException(e);
                }
        }

}
