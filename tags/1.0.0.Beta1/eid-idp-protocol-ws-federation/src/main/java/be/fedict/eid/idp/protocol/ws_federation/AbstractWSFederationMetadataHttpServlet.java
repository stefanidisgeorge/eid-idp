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

package be.fedict.eid.idp.protocol.ws_federation;

import be.fedict.eid.idp.common.AttributeConstants;
import be.fedict.eid.idp.spi.IdentityProviderConfiguration;
import be.fedict.eid.idp.spi.IdentityProviderConfigurationFactory;
import oasis.names.tc.saml._2_0.metadata.*;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xml.security.utils.Constants;
import org.apache.xpath.XPathAPI;
import org.oasis_open.docs.wsfed.authorization._200706.ClaimType;
import org.oasis_open.docs.wsfed.authorization._200706.DescriptionType;
import org.oasis_open.docs.wsfed.authorization._200706.DisplayNameType;
import org.oasis_open.docs.wsfed.federation._200706.ClaimTypesOfferedType;
import org.oasis_open.docs.wsfed.federation._200706.EndpointType;
import org.oasis_open.docs.wsfed.federation._200706.SecurityTokenServiceType;
import org.w3._2000._09.xmldsig_.KeyInfoType;
import org.w3._2000._09.xmldsig_.X509DataType;
import org.w3._2005._08.addressing.AttributedURIType;
import org.w3._2005._08.addressing.EndpointReferenceType;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.UUID;

public abstract class AbstractWSFederationMetadataHttpServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    private static final Log LOG = LogFactory
            .getLog(AbstractWSFederationMetadataHttpServlet.class);

    @Override
    protected void doGet(HttpServletRequest request,
                         HttpServletResponse response) throws ServletException, IOException {
        LOG.debug("doGet");
        response.setContentType("application/samlmetadata+xml");

        IdentityProviderConfiguration configuration = IdentityProviderConfigurationFactory
                .getInstance(request);

        OutputStream outputStream = response.getOutputStream();
        try {
            writeMetadata(request, configuration, outputStream);
        } catch (Exception e) {
            throw new ServletException("error: " + e.getMessage(), e);
        }
    }

    private void writeMetadata(HttpServletRequest request,
                               IdentityProviderConfiguration configuration,
                               OutputStream outputStream) throws JAXBException, ServletException,
            ParserConfigurationException, CertificateEncodingException,
            TransformerFactoryConfigurationError, TransformerException,
            IOException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, MarshalException,
            XMLSignatureException {
        ObjectFactory objectFactory = new ObjectFactory();
        EntityDescriptorType entityDescriptor = objectFactory
                .createEntityDescriptorType();

        String location = "https://" + request.getServerName() + ":"
                + request.getServerPort() + request.getContextPath()
                + "/protocol/" + getPath();
        LOG.debug("location: " + location);
        entityDescriptor.setEntityID(location);
        String id = "saml-metadata-" + UUID.randomUUID().toString();
        entityDescriptor.setID(id);

        org.oasis_open.docs.wsfed.federation._200706.ObjectFactory fedObjectFactory =
                new org.oasis_open.docs.wsfed.federation._200706.ObjectFactory();
        SecurityTokenServiceType securityTokenService = fedObjectFactory
                .createSecurityTokenServiceType();
        List<RoleDescriptorType> roleDescriptors = entityDescriptor
                .getRoleDescriptorOrIDPSSODescriptorOrSPSSODescriptor();
        roleDescriptors.add(securityTokenService);
        securityTokenService.getProtocolSupportEnumeration().add(
                "http://docs.oasis-open.org/wsfed/federation/200706");

        List<EndpointType> passiveRequestorEndpoints = securityTokenService
                .getPassiveRequestorEndpoint();
        EndpointType endpoint = fedObjectFactory.createEndpointType();
        passiveRequestorEndpoints.add(endpoint);

        org.w3._2005._08.addressing.ObjectFactory addrObjectFactory = new org.w3._2005._08.addressing.ObjectFactory();

        EndpointReferenceType endpointReference = addrObjectFactory
                .createEndpointReferenceType();
        endpoint.getEndpointReference().add(endpointReference);
        AttributedURIType address = addrObjectFactory.createAttributedURIType();
        endpointReference.setAddress(address);

        address.setValue(location);

        List<KeyDescriptorType> keyDescriptors = securityTokenService
                .getKeyDescriptor();
        KeyDescriptorType keyDescriptor = objectFactory
                .createKeyDescriptorType();
        keyDescriptors.add(keyDescriptor);
        keyDescriptor.setUse(KeyTypes.SIGNING);
        org.w3._2000._09.xmldsig_.ObjectFactory dsObjectFactory = new org.w3._2000._09.xmldsig_.ObjectFactory();
        KeyInfoType keyInfo = dsObjectFactory.createKeyInfoType();
        keyDescriptor.setKeyInfo(keyInfo);
        List<Object> keyInfoObjects = keyInfo.getContent();
        X509DataType x509Data = dsObjectFactory.createX509DataType();
        keyInfoObjects.add(dsObjectFactory.createX509Data(x509Data));

        KeyStore.PrivateKeyEntry identity = configuration.findIdentity();
        if (null != identity) {
            x509Data.getX509IssuerSerialOrX509SKIOrX509SubjectName().add(
                    dsObjectFactory.createX509DataTypeX509Certificate(identity.getCertificate()
                            .getEncoded()));
        }

        ClaimTypesOfferedType claimTypesOffered = fedObjectFactory
                .createClaimTypesOfferedType();
        securityTokenService.setClaimTypesOffered(claimTypesOffered);
        List<ClaimType> claimTypes = claimTypesOffered.getClaimType();
        org.oasis_open.docs.wsfed.authorization._200706.ObjectFactory authObjectFactory =
                new org.oasis_open.docs.wsfed.authorization._200706.ObjectFactory();

        addClaimType(AttributeConstants.NAME_CLAIM_TYPE_URI,
                "Name", "The name of the Subject.",
                authObjectFactory, claimTypes);
        addClaimType(AttributeConstants.FIRST_NAME_CLAIM_TYPE_URI,
                "FirstName", "Preferred name or first name of a Subject.",
                authObjectFactory, claimTypes);
        addClaimType(AttributeConstants.LAST_NAME_CLAIM_TYPE_URI,
                "LastName", "Surname or family name of a Subject.",
                authObjectFactory, claimTypes);
        addClaimType(AttributeConstants.STREET_ADDRESS_CLAIM_TYPE_URI,
                "StreetAddress",
                "Street address component of a Subject's address information.",
                authObjectFactory, claimTypes);
        addClaimType(
                AttributeConstants.LOCALITY_CLAIM_TYPE_URI,
                "Locality",
                "This attribute contains the name of a locality, such as a city, county or other geographic region.",
                authObjectFactory, claimTypes);
        addClaimType(
                AttributeConstants.POSTAL_CODE_CLAIM_TYPE_URI,
                "PostalCode",
                "The postal code attribute type specifies the postal code of the named object.",
                authObjectFactory, claimTypes);
        addClaimType(AttributeConstants.COUNTRY_CLAIM_TYPE_URI, "Country",
                "This attribute contains a two-letter ISO 3166 country code.",
                authObjectFactory, claimTypes);
        addClaimType(
                AttributeConstants.DATE_OF_BIRTH_CLAIM_TYPE_URI,
                "DateOfBirth",
                "The date of birth of a Subject in a form allowed by the xs:date data type.",
                authObjectFactory, claimTypes);
        addClaimType(
                AttributeConstants.GENDER_CLAIM_TYPE_URI,
                "Gender",
                "Gender of a Subject that can have any of these exact string values – '0' (meaning unspecified), '1' (meaning Male) or '2' (meaning Female). Using these values allows them to be language neutral.",
                authObjectFactory, claimTypes);
        addClaimType(
                AttributeConstants.PPID_CLAIM_TYPE_URI,
                "PPID",
                "A private personal identifier (PPID) that identifies the Subject to a Relying Party.",
                authObjectFactory, claimTypes);

        addClaimType(
                AttributeConstants.NATIONALITY_CLAIM_TYPE_URI,
                "Nationality",
                "The nationality of the named object.",
                authObjectFactory, claimTypes);

        addClaimType(
                AttributeConstants.PLACE_OF_BIRTH_CLAIM_TYPE_URI,
                "PlaceOfBirth",
                "The place of birth of the named object.",
                authObjectFactory, claimTypes);

        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory
                .newInstance();
        documentBuilderFactory.setNamespaceAware(true);
        DocumentBuilder documentBuilder = documentBuilderFactory
                .newDocumentBuilder();
        Document document = documentBuilder.newDocument();

        JAXBContext context = JAXBContext
                .newInstance(
                        ObjectFactory.class,
                        org.oasis_open.docs.wsfed.federation._200706.ObjectFactory.class);
        Marshaller marshaller = context.createMarshaller();
        marshaller.setProperty("com.sun.xml.bind.namespacePrefixMapper",
                new WSFederationNamespacePrefixMapper());
        marshaller.marshal(objectFactory
                .createEntityDescriptor(entityDescriptor), document);

        if (null != identity) {
            signDocument(document, identity.getPrivateKey(),
                    (X509Certificate) identity.getCertificate(), id);
        }

        writeDocument(document, outputStream);
    }

    private void addClaimType(
            String claimUri,
            String displayName,
            String description,
            org.oasis_open.docs.wsfed.authorization._200706.ObjectFactory authObjectFactory,
            List<ClaimType> claimTypes) {
        ClaimType claim = authObjectFactory.createClaimType();
        claimTypes.add(claim);
        claim.setUri(claimUri);
        claim.setOptional(true);
        DisplayNameType claimDisplayName = authObjectFactory
                .createDisplayNameType();
        claimDisplayName.setValue(displayName);
        claim.setDisplayName(claimDisplayName);
        DescriptionType claimDescription = authObjectFactory
                .createDescriptionType();
        claimDescription.setValue(description);
        claim.setDescription(claimDescription);
    }

    private void signDocument(Document document, PrivateKey privateKey,
                              X509Certificate certificate, String documentId)
            throws TransformerException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, MarshalException,
            XMLSignatureException {

        Element nsElement = document.createElement("ns");
        nsElement.setAttributeNS(Constants.NamespaceSpecNS, "xmlns:md",
                "urn:oasis:names:tc:SAML:2.0:metadata");
        Node roleDescriptorNode = XPathAPI.selectSingleNode(document,
                "//md:RoleDescriptor", nsElement);
        if (null == roleDescriptorNode) {
            throw new IllegalStateException(
                    "RoleDescriptor element not present");
        }

        XMLSignatureFactory signatureFactory = XMLSignatureFactory.getInstance(
                "DOM", new org.jcp.xml.dsig.internal.dom.XMLDSigRI());

        XMLSignContext signContext = new DOMSignContext(privateKey, document
                .getDocumentElement(), roleDescriptorNode);
        signContext.putNamespacePrefix(
                javax.xml.crypto.dsig.XMLSignature.XMLNS, "ds");
        DigestMethod digestMethod = signatureFactory.newDigestMethod(
                DigestMethod.SHA1, null);

        List<Transform> transforms = new LinkedList<Transform>();
        transforms.add(signatureFactory.newTransform(Transform.ENVELOPED,
                (TransformParameterSpec) null));
        Transform exclusiveTransform = signatureFactory
                .newTransform(CanonicalizationMethod.EXCLUSIVE,
                        (TransformParameterSpec) null);
        transforms.add(exclusiveTransform);

        Reference reference = signatureFactory.newReference("#" + documentId,
                digestMethod, transforms, null, null);

        SignatureMethod signatureMethod = signatureFactory.newSignatureMethod(
                SignatureMethod.RSA_SHA1, null);
        CanonicalizationMethod canonicalizationMethod = signatureFactory
                .newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE,
                        (C14NMethodParameterSpec) null);
        SignedInfo signedInfo = signatureFactory.newSignedInfo(
                canonicalizationMethod, signatureMethod, Collections
                .singletonList(reference));

        List<Object> keyInfoContent = new LinkedList<Object>();
        KeyInfoFactory keyInfoFactory = KeyInfoFactory.getInstance();
        List<Object> x509DataObjects = new LinkedList<Object>();
        x509DataObjects.add(certificate);
        X509Data x509Data = keyInfoFactory.newX509Data(x509DataObjects);
        keyInfoContent.add(x509Data);
        KeyInfo keyInfo = keyInfoFactory.newKeyInfo(keyInfoContent);

        javax.xml.crypto.dsig.XMLSignature xmlSignature = signatureFactory
                .newXMLSignature(signedInfo, keyInfo);
        xmlSignature.sign(signContext);
    }

    protected void writeDocument(Document document,
                                 OutputStream documentOutputStream)
            throws TransformerFactoryConfigurationError, TransformerException,
            IOException {
        Result result = new StreamResult(documentOutputStream);
        Transformer xformer = TransformerFactory.newInstance().newTransformer();
        Source source = new DOMSource(document);
        xformer.transform(source, result);
    }

    protected abstract String getPath();
}
