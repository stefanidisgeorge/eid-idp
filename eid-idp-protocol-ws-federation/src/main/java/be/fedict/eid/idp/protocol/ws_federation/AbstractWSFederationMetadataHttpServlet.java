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
import be.fedict.eid.idp.common.saml2.Saml2Util;
import be.fedict.eid.idp.protocol.ws_federation.wsfed.*;
import be.fedict.eid.idp.spi.IdentityProviderConfiguration;
import be.fedict.eid.idp.spi.IdentityProviderConfigurationFactory;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xml.security.utils.Constants;
import org.apache.xpath.XPathAPI;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml2.metadata.RoleDescriptor;
import org.opensaml.ws.wsaddressing.Address;
import org.opensaml.ws.wsaddressing.EndpointReference;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.keyinfo.KeyInfoHelper;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.bind.JAXBException;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
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
                    ClaimType.DEFAULT_ELEMENT_NAME,
                    new ClaimTypeBuilder(),
                    new ClaimTypeMarshaller(),
                    new ClaimTypeUnmarshaller());

            Configuration.registerObjectProvider(
                    ClaimTypesOffered.DEFAULT_ELEMENT_NAME,
                    new ClaimTypesOfferedBuilder(),
                    new ClaimTypesOfferedMarshaller(),
                    new ClaimTypesOfferedUnmarshaller());

            Configuration.registerObjectProvider(
                    Description.DEFAULT_ELEMENT_NAME,
                    new DescriptionBuilder(),
                    new DescriptionMarshaller(),
                    new DescriptionUnmarshaller());

            Configuration.registerObjectProvider(
                    DisplayName.DEFAULT_ELEMENT_NAME,
                    new DisplayNameBuilder(),
                    new DisplayNameMarshaller(),
                    new DisplayNameUnmarshaller());

            Configuration.registerObjectProvider(
                    PassiveRequestorEndpoint.DEFAULT_ELEMENT_NAME,
                    new PassiveRequestorEndpointBuilder(),
                    new PassiveRequestorEndpointMarshaller(),
                    new PassiveRequestorEndpointUnmarshaller());

            Configuration.registerObjectProvider(
                    SecurityTokenService.DEFAULT_ELEMENT_NAME,
                    new SecurityTokenServiceBuilder(),
                    new SecurityTokenServiceMarshaller(),
                    new SecurityTokenServiceUnmarshaller());

            Configuration.registerObjectProvider(
                    SecurityTokenService.TYPE_NAME,
                    new SecurityTokenServiceBuilder(),
                    new SecurityTokenServiceMarshaller(),
                    new SecurityTokenServiceUnmarshaller());


        } catch (ConfigurationException e) {
            throw new RuntimeException("could not bootstrap the OpenSAML2 library", e);
        }
    }

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

        String location = "https://" + request.getServerName() + ":"
                + request.getServerPort() + request.getContextPath()
                + "/protocol/" + getPath();
        LOG.debug("location: " + location);

        EntityDescriptor ed = Saml2Util.buildXMLObject(EntityDescriptor.class,
                EntityDescriptor.DEFAULT_ELEMENT_NAME);
        ed.setEntityID(location);
        ed.setID("saml-metadata-" + UUID.randomUUID().toString());

        XMLObjectBuilder<SecurityTokenService> builder =
                Configuration.getBuilderFactory().getBuilder(SecurityTokenService.TYPE_NAME);
        SecurityTokenService securityTokenService = builder.buildObject(
                RoleDescriptor.DEFAULT_ELEMENT_NAME, SecurityTokenService.TYPE_NAME);

//        SecurityTokenService securityTokenService = Saml2Util.buildXMLObject(
//                SecurityTokenService.class,
//                SecurityTokenService.DEFAULT_ELEMENT_NAME);
        ed.getRoleDescriptors().add(securityTokenService);

        securityTokenService.addSupportedProtocol("http://docs.oasis-open.org/wsfed/federation/200706");

        PassiveRequestorEndpoint passiveRequestorEndpoint =
                Saml2Util.buildXMLObject(PassiveRequestorEndpoint.class,
                        PassiveRequestorEndpoint.DEFAULT_ELEMENT_NAME);
        securityTokenService.getPassiveRequestorEndpoints().add(passiveRequestorEndpoint);

        EndpointReference endpoint =
                Saml2Util.buildXMLObject(EndpointReference.class,
                        EndpointReference.ELEMENT_NAME);
        passiveRequestorEndpoint.setEndpointReference(endpoint);

        Address address = Saml2Util.buildXMLObject(Address.class,
                Address.ELEMENT_NAME);
        endpoint.setAddress(address);
        address.setValue(location);

        KeyDescriptor keyDescriptor =
                Saml2Util.buildXMLObject(KeyDescriptor.class,
                        KeyDescriptor.DEFAULT_ELEMENT_NAME);
        securityTokenService.getKeyDescriptors().add(keyDescriptor);
        keyDescriptor.setUse(UsageType.SIGNING);

        org.opensaml.xml.signature.KeyInfo keyInfo =
                Saml2Util.buildXMLObject(org.opensaml.xml.signature.KeyInfo.class,
                        org.opensaml.xml.signature.KeyInfo.DEFAULT_ELEMENT_NAME);
        keyDescriptor.setKeyInfo(keyInfo);

        KeyStore.PrivateKeyEntry identity = configuration.findIdentity();
        try {
            if (null != identity) {
                KeyInfoHelper.addCertificate(keyInfo, (X509Certificate) identity.getCertificate());
            }
        } catch (CertificateEncodingException e) {
            throw new RuntimeException("opensaml2 certificate encoding error: " + e.getMessage(), e);
        }

        // claims
        ClaimTypesOffered claimTypesOffered =
                Saml2Util.buildXMLObject(ClaimTypesOffered.class,
                        ClaimTypesOffered.DEFAULT_ELEMENT_NAME);
        securityTokenService.setClaimTypesOffered(claimTypesOffered);


        List<ClaimType> claimTypes = claimTypesOffered.getClaimTypes();

        addClaimType(AttributeConstants.NAME_CLAIM_TYPE_URI,
                "Name", "The name of the Subject.", claimTypes);
        addClaimType(AttributeConstants.FIRST_NAME_CLAIM_TYPE_URI,
                "FirstName", "Preferred name or first name of a Subject.",
                claimTypes);
        addClaimType(AttributeConstants.LAST_NAME_CLAIM_TYPE_URI,
                "LastName", "Surname or family name of a Subject.",
                claimTypes);
        addClaimType(AttributeConstants.STREET_ADDRESS_CLAIM_TYPE_URI,
                "StreetAddress",
                "Street address component of a Subject's address information.",
                claimTypes);
        addClaimType(
                AttributeConstants.LOCALITY_CLAIM_TYPE_URI,
                "Locality",
                "This attribute contains the name of a locality, such as a city, county or other geographic region.",
                claimTypes);
        addClaimType(
                AttributeConstants.POSTAL_CODE_CLAIM_TYPE_URI,
                "PostalCode",
                "The postal code attribute type specifies the postal code of the named object.",
                claimTypes);
        addClaimType(AttributeConstants.COUNTRY_CLAIM_TYPE_URI, "Country",
                "This attribute contains a two-letter ISO 3166 country code.",
                claimTypes);
        addClaimType(
                AttributeConstants.DATE_OF_BIRTH_CLAIM_TYPE_URI,
                "DateOfBirth",
                "The date of birth of a Subject in a form allowed by the xs:date data type.",
                claimTypes);
        addClaimType(
                AttributeConstants.GENDER_CLAIM_TYPE_URI,
                "Gender",
                "Gender of a Subject that can have any of these exact string values – '0' (meaning unspecified), '1' (meaning Male) or '2' (meaning Female). Using these values allows them to be language neutral.",
                claimTypes);
        addClaimType(
                AttributeConstants.PPID_CLAIM_TYPE_URI,
                "PPID",
                "A private personal identifier (PPID) that identifies the Subject to a Relying Party.",
                claimTypes);

        addClaimType(
                AttributeConstants.NATIONALITY_CLAIM_TYPE_URI,
                "Nationality",
                "The nationality of the named object.",
                claimTypes);

        addClaimType(
                AttributeConstants.PLACE_OF_BIRTH_CLAIM_TYPE_URI,
                "PlaceOfBirth",
                "The place of birth of the named object.",
                claimTypes);

        addClaimType(
                AttributeConstants.PHOTO_CLAIM_TYPE_URI,
                "Photo",
                "Base64 encoded photo of the named object.",
                claimTypes);

        Element element;
        if (null != identity) {

            LOG.debug("sign WS-Federation Metadata");
            element = Saml2Util.signAsElement(ed, ed,
                    (X509Certificate) identity.getCertificate(),
                    identity.getPrivateKey());
        } else {

            // TODO: explode here? will fail at RP for sure if not signed so ...
            LOG.warn("assertion NOT signed!");
            element = Saml2Util.marshall(ed);
        }

//        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        Saml2Util.writeDocument(element.getOwnerDocument(), outputStream);
//        return new String(outputStream.toByteArray());


//        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory
//                .newInstance();
//        documentBuilderFactory.setNamespaceAware(true);
//        DocumentBuilder documentBuilder = documentBuilderFactory
//                .newDocumentBuilder();
//        Document document = documentBuilder.newDocument();
//
//        JAXBContext context = JAXBContext
//                .newInstance(
//                        ObjectFactory.class,
//                        org.oasis_open.docs.wsfed.federation._200706.ObjectFactory.class);
//        Marshaller marshaller = context.createMarshaller();
//        marshaller.setProperty("com.sun.xml.bind.namespacePrefixMapper",
//                new WSFederationNamespacePrefixMapper());
//        marshaller.marshal(objectFactory
//                .createEntityDescriptor(entityDescriptor), document);
//
//        if (null != identity) {
//            signDocument(document, identity.getPrivateKey(),
//                    (X509Certificate) identity.getCertificate(), id);
//        }
//
//        writeDocument(document, outputStream);
    }

    private void addClaimType(
            String claimUri,
            String displayName,
            String description,
            List<ClaimType> claimTypes) {

        ClaimType claim = Saml2Util.buildXMLObject(ClaimType.class,
                ClaimType.DEFAULT_ELEMENT_NAME);
        claimTypes.add(claim);
        claim.setUri(claimUri);
        claim.setOptional(true);

        DisplayName claimDisplayName =
                Saml2Util.buildXMLObject(DisplayName.class,
                        DisplayName.DEFAULT_ELEMENT_NAME);
        claimDisplayName.setValue(displayName);
        claim.setDisplayName(claimDisplayName);

        Description claimDescription =
                Saml2Util.buildXMLObject(Description.class,
                        Description.DEFAULT_ELEMENT_NAME);
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
