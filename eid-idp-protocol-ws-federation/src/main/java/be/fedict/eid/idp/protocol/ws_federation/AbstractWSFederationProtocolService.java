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

import be.fedict.eid.applet.service.Address;
import be.fedict.eid.applet.service.Identity;
import be.fedict.eid.idp.common.AttributeConstants;
import be.fedict.eid.idp.spi.IdentityProviderConfiguration;
import be.fedict.eid.idp.spi.IdentityProviderFlow;
import be.fedict.eid.idp.spi.IdentityProviderProtocolService;
import be.fedict.eid.idp.spi.ReturnResponse;
import oasis.names.tc.saml._2_0.assertion.*;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xml.security.utils.Constants;
import org.apache.xpath.XPathAPI;
import org.joda.time.DateTime;
import org.oasis_open.docs.ws_sx.ws_trust._200512.ObjectFactory;
import org.oasis_open.docs.ws_sx.ws_trust._200512.RequestSecurityTokenResponseCollectionType;
import org.oasis_open.docs.ws_sx.ws_trust._200512.RequestSecurityTokenResponseType;
import org.oasis_open.docs.ws_sx.ws_trust._200512.RequestedSecurityTokenType;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
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
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * WS-Federation Web (Passive) Requestors. We could use OpenAM (OpenSS0), but
 * then again they're also just doing a wrapping around the JAXB classes.
 *
 * @author Frank Cornelis
 */
public abstract class AbstractWSFederationProtocolService implements
        IdentityProviderProtocolService {

    private static final Log LOG = LogFactory
            .getLog(AbstractWSFederationProtocolService.class);

    public static final String WCTX_SESSION_ATTRIBUTE =
            AbstractWSFederationProtocolService.class.getName() + ".wctx";

    public static final String WTREALM_SESSION_ATTRIBUTE =
            AbstractWSFederationProtocolService.class.getName() + ".wtrealm";

    private IdentityProviderConfiguration configuration;

    private void storeWCtx(String wctx, HttpServletRequest request) {
        HttpSession httpSession = request.getSession();
        httpSession.setAttribute(WCTX_SESSION_ATTRIBUTE, wctx);
    }

    private String retrieveWctx(HttpSession httpSession) {
        return (String) httpSession.getAttribute(WCTX_SESSION_ATTRIBUTE);
    }

    private void storeWtrealm(String wtrealm, HttpServletRequest request) {
        HttpSession httpSession = request.getSession();
        httpSession.setAttribute(WTREALM_SESSION_ATTRIBUTE, wtrealm);
    }

    private String retrieveWtrealm(HttpSession httpSession) {
        return (String) httpSession
                .getAttribute(WTREALM_SESSION_ATTRIBUTE);
    }

    @Override
    public IdentityProviderFlow handleIncomingRequest(
            HttpServletRequest request, HttpServletResponse response)
            throws Exception {
        LOG.debug("handleIncomingRequest");
        String wa = request.getParameter("wa");
        if (null == wa) {
            throw new ServletException("wa parameter missing");
        }
        if (!"wsignin1.0".equals(wa)) {
            throw new ServletException("wa action not \"wsignin1.0\"");
        }
        String wtrealm = request.getParameter("wtrealm");
        if (null == wtrealm) {
            throw new ServletException("missing wtrealm parameter");
        }
        LOG.debug("wtrealm: " + wtrealm);
        storeWtrealm(wtrealm, request);
        String wctx = request.getParameter("wctx");
        LOG.debug("wctx: " + wctx);
        storeWCtx(wctx, request);
        return getAuthenticationFlow();
    }

    @Override
    public ReturnResponse handleReturnResponse(HttpSession httpSession,
                                               String userId,
                                               String givenName, String surName,
                                               Identity identity, Address address,
                                               HttpServletRequest request,
                                               HttpServletResponse response)
            throws Exception {
        LOG.debug("handleReturnResponse");
        String wtrealm = retrieveWtrealm(httpSession);
        ReturnResponse returnResponse = new ReturnResponse(wtrealm);
        returnResponse.addAttribute("wa", "wsignin1.0");
        String wctx = retrieveWctx(httpSession);
        returnResponse.addAttribute("wctx", wctx);

        String wresult = getWResult(wctx, wtrealm, userId, givenName, surName,
                identity, address);
        returnResponse.addAttribute("wresult", wresult);
        return returnResponse;
    }

    private String getWResult(String wctx, String wtrealm,
                              String userId,
                              String givenName, String surName,
                              Identity identity,
                              Address address)
            throws JAXBException, DatatypeConfigurationException,
            ParserConfigurationException, TransformerException,
            NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            MarshalException, XMLSignatureException,
            TransformerFactoryConfigurationError, IOException {
        ObjectFactory trustObjectFactory = new ObjectFactory();
        RequestSecurityTokenResponseCollectionType requestSecurityTokenResponseCollection = trustObjectFactory
                .createRequestSecurityTokenResponseCollectionType();

        List<RequestSecurityTokenResponseType> requestSecurityTokenResponses = requestSecurityTokenResponseCollection
                .getRequestSecurityTokenResponse();
        RequestSecurityTokenResponseType requestSecurityTokenResponse = trustObjectFactory
                .createRequestSecurityTokenResponseType();
        requestSecurityTokenResponses.add(requestSecurityTokenResponse);

        if (null != wctx) {
            requestSecurityTokenResponse.setContext(wctx);
        }

        List<Object> requestSecurityTokenResponseContent = requestSecurityTokenResponse
                .getAny();

        requestSecurityTokenResponseContent.add(trustObjectFactory
                .createTokenType("urn:oasis:names:tc:SAML:2.0:assertion"));
        requestSecurityTokenResponseContent
                .add(trustObjectFactory
                        .createRequestType("http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue"));
        requestSecurityTokenResponseContent
                .add(trustObjectFactory
                        .createKeyType("http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer"));

        RequestedSecurityTokenType requestedSecurityToken = trustObjectFactory
                .createRequestedSecurityTokenType();
        requestSecurityTokenResponseContent.add(trustObjectFactory
                .createRequestedSecurityToken(requestedSecurityToken));

        oasis.names.tc.saml._2_0.assertion.ObjectFactory samlObjectFactory = new oasis.names.tc.saml._2_0.assertion.ObjectFactory();
        AssertionType assertion = samlObjectFactory.createAssertionType();
        requestedSecurityToken.setAny(samlObjectFactory
                .createAssertion(assertion));

        AttributeStatementType attributeStatement = samlObjectFactory
                .createAttributeStatementType();
        assertion.getStatementOrAuthnStatementOrAuthzDecisionStatement().add(
                attributeStatement);
        /*
           * Maybe we should be using OpenSAML2 here instead of the JAXB binding?
           */
        assertion.setVersion("2.0");
        String assertionId = "saml-" + UUID.randomUUID().toString();
        assertion.setID(assertionId);
        DatatypeFactory datatypeFactory = DatatypeFactory.newInstance();
        DateTime issueInstantDateTime = new DateTime();
        GregorianCalendar issueInstantCalendar = issueInstantDateTime
                .toGregorianCalendar();
        assertion.setIssueInstant(datatypeFactory
                .newXMLGregorianCalendar(issueInstantCalendar));
        NameIDType issuer = samlObjectFactory.createNameIDType();

        KeyStore.PrivateKeyEntry idPIdentity = this.configuration.findIdentity();
        if (null != idPIdentity) {
            issuer.setValue(((X509Certificate) idPIdentity.getCertificate()).getSubjectX500Principal().toString());
        } else {
            issuer.setValue("http://www.e-contract.be/"); // TODO
        }
        assertion.setIssuer(issuer);

        SubjectType subject = samlObjectFactory.createSubjectType();
        assertion.setSubject(subject);
        NameIDType nameId = samlObjectFactory.createNameIDType();
        nameId.setValue(userId);
        subject.getContent().add(samlObjectFactory.createNameID(nameId));

        SubjectConfirmationType subjectConfirmation = samlObjectFactory
                .createSubjectConfirmationType();
        subject.getContent().add(
                samlObjectFactory
                        .createSubjectConfirmation(subjectConfirmation));
        subjectConfirmation.setMethod("urn:oasis:names:tc:SAML:2.0:cm:bearer");

        List<Object> attributes = attributeStatement
                .getAttributeOrEncryptedAttribute();

        addAttribute(AttributeConstants.FIRST_NAME_CLAIM_TYPE_URI, givenName,
                samlObjectFactory, attributes);
        addAttribute(AttributeConstants.LAST_NAME_CLAIM_TYPE_URI, surName,
                samlObjectFactory, attributes);
        addAttribute(AttributeConstants.NAME_CLAIM_TYPE_URI,
                givenName + " " + surName,
                samlObjectFactory, attributes);
        addAttribute(AttributeConstants.COUNTRY_CLAIM_TYPE_URI, "BE",
                samlObjectFactory, attributes);

        if (null != identity) {
            String genderValue;
            switch (identity.getGender()) {
                case MALE:
                    genderValue = "1";
                    break;
                case FEMALE:
                    genderValue = "2";
                    break;
                default:
                    genderValue = "0";
                    break;
            }
            addAttribute(AttributeConstants.GENDER_CLAIM_TYPE_URI, genderValue,
                    samlObjectFactory, attributes);

            addAttribute(AttributeConstants.PPID_CLAIM_TYPE_URI,
                    userId, samlObjectFactory, attributes);

            AttributeType dobAttribute = samlObjectFactory.createAttributeType();
            attributes.add(dobAttribute);
            dobAttribute
                    .setName(AttributeConstants.DATE_OF_BIRTH_CLAIM_TYPE_URI);
            dobAttribute.getAttributeValue().add(
                    datatypeFactory.newXMLGregorianCalendar(identity
                            .getDateOfBirth()));

            addAttribute(AttributeConstants.NATIONALITY_CLAIM_TYPE_URI,
                    identity.getNationality(), samlObjectFactory, attributes);
            addAttribute(AttributeConstants.PLACE_OF_BIRTH_CLAIM_TYPE_URI,
                    identity.getPlaceOfBirth(), samlObjectFactory, attributes);

        }

        if (null != address) {

            addAttribute(AttributeConstants.STREET_ADDRESS_CLAIM_TYPE_URI,
                    address.getStreetAndNumber(), samlObjectFactory, attributes);
            addAttribute(AttributeConstants.LOCALITY_CLAIM_TYPE_URI, address
                    .getMunicipality(), samlObjectFactory, attributes);
            addAttribute(AttributeConstants.POSTAL_CODE_CLAIM_TYPE_URI, address
                    .getZip(), samlObjectFactory, attributes);

        }

        ConditionsType conditions = samlObjectFactory.createConditionsType();
        assertion.setConditions(conditions);
        DateTime notBeforeDateTime = issueInstantDateTime;
        DateTime notAfterDateTime = notBeforeDateTime.plusHours(1);
        conditions.setNotBefore(datatypeFactory
                .newXMLGregorianCalendar(notBeforeDateTime
                        .toGregorianCalendar()));
        conditions
                .setNotOnOrAfter(datatypeFactory
                        .newXMLGregorianCalendar(notAfterDateTime
                                .toGregorianCalendar()));
        List<ConditionAbstractType> conditionList = conditions
                .getConditionOrAudienceRestrictionOrOneTimeUse();
        AudienceRestrictionType audienceRestriction = samlObjectFactory
                .createAudienceRestrictionType();
        audienceRestriction.getAudience().add(wtrealm);
        conditionList.add(audienceRestriction);

        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory
                .newInstance();
        documentBuilderFactory.setNamespaceAware(true);
        DocumentBuilder documentBuilder = documentBuilderFactory
                .newDocumentBuilder();
        Document document = documentBuilder.newDocument();

        JAXBContext context = JAXBContext.newInstance(ObjectFactory.class,
                oasis.names.tc.saml._2_0.assertion.ObjectFactory.class);
        Marshaller marshaller = context.createMarshaller();
        marshaller.setProperty("com.sun.xml.bind.namespacePrefixMapper",
                new WSFederationNamespacePrefixMapper());
        marshaller
                .marshal(
                        trustObjectFactory
                                .createRequestSecurityTokenResponseCollection(requestSecurityTokenResponseCollection),
                        document);

        signDocument(document, assertionId);

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        writeDocument(document, outputStream);
        return new String(outputStream.toByteArray());
    }

    private void addAttribute(String attributeUri, String attributeValue,
                              oasis.names.tc.saml._2_0.assertion.ObjectFactory samlObjectFactory,
                              List<Object> attributes) {
        AttributeType attribute = samlObjectFactory.createAttributeType();
        attributes.add(attribute);
        attribute.setName(attributeUri);
        attribute.getAttributeValue().add(attributeValue);
    }

    private void writeDocument(Document document,
                               OutputStream documentOutputStream)
            throws TransformerFactoryConfigurationError, TransformerException,
            IOException {
        Result result = new StreamResult(documentOutputStream);
        Transformer xformer = TransformerFactory.newInstance().newTransformer();
        Source source = new DOMSource(document);
        xformer.transform(source, result);
    }

    private void signDocument(Document document, String assertionId)
            throws TransformerException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, MarshalException,
            XMLSignatureException {
        Element nsElement = document.createElement("ns");
        nsElement.setAttributeNS(Constants.NamespaceSpecNS, "xmlns:saml",
                "urn:oasis:names:tc:SAML:2.0:assertion");
        Node samlAssertionNode = XPathAPI.selectSingleNode(document,
                "//saml:Assertion", nsElement);
        if (null == samlAssertionNode) {
            throw new IllegalStateException(
                    "saml:Assertion element not present");
        }
        Node samlSubjectNode = XPathAPI.selectSingleNode(samlAssertionNode,
                "saml:Subject", nsElement);
        if (null == samlSubjectNode) {
            throw new IllegalStateException("saml:Subject element not present");
        }

        KeyStore.PrivateKeyEntry identity = this.configuration.findIdentity();

        if (null != identity) {
            XMLSignatureFactory signatureFactory = XMLSignatureFactory.getInstance(
                    "DOM", new org.jcp.xml.dsig.internal.dom.XMLDSigRI());

            XMLSignContext signContext = new DOMSignContext(identity.getPrivateKey(),
                    samlAssertionNode, samlSubjectNode);
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

            Reference reference = signatureFactory.newReference("#" + assertionId,
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
            x509DataObjects.add(identity.getCertificate());
            X509Data x509Data = keyInfoFactory.newX509Data(x509DataObjects);
            keyInfoContent.add(x509Data);
            KeyInfo keyInfo = keyInfoFactory.newKeyInfo(keyInfoContent);

            javax.xml.crypto.dsig.XMLSignature xmlSignature = signatureFactory
                    .newXMLSignature(signedInfo, keyInfo);
            xmlSignature.sign(signContext);
        }
    }

    @Override
    public void init(ServletContext servletContext,
                     IdentityProviderConfiguration configuration) {
        LOG.debug("init");
        this.configuration = configuration;
    }

    protected abstract IdentityProviderFlow getAuthenticationFlow();
}
