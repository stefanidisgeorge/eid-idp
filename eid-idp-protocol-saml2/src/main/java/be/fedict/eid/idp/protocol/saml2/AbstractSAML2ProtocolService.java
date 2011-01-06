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

package be.fedict.eid.idp.protocol.saml2;

import be.fedict.eid.applet.service.Address;
import be.fedict.eid.applet.service.Identity;
import be.fedict.eid.idp.common.AttributeConstants;
import be.fedict.eid.idp.spi.*;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.common.binding.decoding.SAMLMessageDecoder;
import org.opensaml.saml2.binding.decoding.HTTPPostDecoder;
import org.opensaml.saml2.core.*;
import org.opensaml.ws.transport.OutTransport;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.schema.XSBase64Binary;
import org.opensaml.xml.schema.XSDateTime;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.util.Base64;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.UUID;

/**
 * SAML2 Browser POST Profile protocol service.
 *
 * @author Frank Cornelis
 */
public abstract class AbstractSAML2ProtocolService implements IdentityProviderProtocolService {

    private static final Log LOG = LogFactory
            .getLog(AbstractSAML2ProtocolService.class);

    private IdentityProviderConfiguration configuration;

    public static final String TARGET_URL_SESSION_ATTRIBUTE = AbstractSAML2ProtocolService.class
            .getName()
            + ".TargetUrl";

    public static final String RELAY_STATE_SESSION_ATTRIBUTE = AbstractSAML2ProtocolService.class
            .getName()
            + ".RelayState";

    public static final String IN_RESPONSE_TO_SESSION_ATTRIBUTE = AbstractSAML2ProtocolService.class
            .getName()
            + ".InResponseTo";

    private void setTargetUrl(String targetUrl, HttpServletRequest request) {
        HttpSession httpSession = request.getSession();
        httpSession.setAttribute(TARGET_URL_SESSION_ATTRIBUTE, targetUrl);
    }

    private String getTargetUrl(HttpSession httpSession) {
        return (String) httpSession
                .getAttribute(TARGET_URL_SESSION_ATTRIBUTE);
    }

    private void setInResponseTo(String inResponseTo, HttpServletRequest request) {
        HttpSession httpSession = request.getSession();
        httpSession
                .setAttribute(IN_RESPONSE_TO_SESSION_ATTRIBUTE, inResponseTo);
    }

    private String getInResponseTo(HttpSession httpSession) {
        return (String) httpSession
                .getAttribute(IN_RESPONSE_TO_SESSION_ATTRIBUTE);
    }

    private void setRelayState(String relayState, HttpServletRequest request) {
        HttpSession httpSession = request.getSession();
        httpSession.setAttribute(RELAY_STATE_SESSION_ATTRIBUTE, relayState);
    }

    private String getRelayState(HttpSession httpSession) {
        return (String) httpSession
                .getAttribute(RELAY_STATE_SESSION_ATTRIBUTE);
    }

    private XMLObjectBuilderFactory builderFactory;

    private SAMLObjectBuilder<Response> responseBuilder;
    private SAMLObjectBuilder<Status> statusBuilder;
    private SAMLObjectBuilder<StatusCode> statusCodeBuilder;
    private SAMLObjectBuilder<Assertion> assertionBuilder;
    private SAMLObjectBuilder<Issuer> issuerBuilder;
    private SAMLObjectBuilder<Conditions> conditionsBuilder;
    private SAMLObjectBuilder<AudienceRestriction> audienceRestrictionBuilder;
    private SAMLObjectBuilder<Audience> audienceBuilder;
    private SAMLObjectBuilder<Subject> subjectBuilder;
    private SAMLObjectBuilder<NameID> nameIdBuilder;
    private SAMLObjectBuilder<SubjectConfirmation> subjectConfirmationBuilder;
    private SAMLObjectBuilder<AuthnStatement> authnStatementBuilder;
    private SAMLObjectBuilder<SubjectConfirmationData> subjectConfirmationDataBuilder;
    private SAMLObjectBuilder<AuthnContext> authnContextBuilder;
    private SAMLObjectBuilder<AttributeStatement> attributeStatementBuilder;
    private SAMLObjectBuilder<Attribute> attributeBuilder;
    private XMLObjectBuilder<XSString> stringBuilder;
    private XMLObjectBuilder<XSDateTime> dateBuilder;
    private XMLObjectBuilder<XSBase64Binary> base64BinaryBuilder;

    @SuppressWarnings("unchecked")
    public void init(ServletContext servletContext,
                     IdentityProviderConfiguration configuration) {
        LOG.debug("init");
        this.configuration = configuration;

        try {
            DefaultBootstrap.bootstrap();
        } catch (ConfigurationException e) {
            throw new RuntimeException("OpenSAML configuration error: "
                    + e.getMessage(), e);
        }
        this.builderFactory = Configuration.getBuilderFactory();
        this.responseBuilder = (SAMLObjectBuilder<Response>) builderFactory
                .getBuilder(Response.DEFAULT_ELEMENT_NAME);
        this.statusBuilder = (SAMLObjectBuilder<Status>) builderFactory
                .getBuilder(Status.DEFAULT_ELEMENT_NAME);
        this.statusCodeBuilder = (SAMLObjectBuilder<StatusCode>) builderFactory
                .getBuilder(StatusCode.DEFAULT_ELEMENT_NAME);
        this.assertionBuilder = (SAMLObjectBuilder<Assertion>) builderFactory
                .getBuilder(Assertion.DEFAULT_ELEMENT_NAME);
        this.issuerBuilder = (SAMLObjectBuilder<Issuer>) builderFactory
                .getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
        this.conditionsBuilder = (SAMLObjectBuilder<Conditions>) builderFactory
                .getBuilder(Conditions.DEFAULT_ELEMENT_NAME);
        this.audienceRestrictionBuilder = (SAMLObjectBuilder<AudienceRestriction>) builderFactory
                .getBuilder(AudienceRestriction.DEFAULT_ELEMENT_NAME);
        this.audienceBuilder = (SAMLObjectBuilder<Audience>) builderFactory
                .getBuilder(Audience.DEFAULT_ELEMENT_NAME);
        this.subjectBuilder = (SAMLObjectBuilder<Subject>) builderFactory
                .getBuilder(Subject.DEFAULT_ELEMENT_NAME);
        this.nameIdBuilder = (SAMLObjectBuilder<NameID>) builderFactory
                .getBuilder(NameID.DEFAULT_ELEMENT_NAME);
        this.subjectConfirmationBuilder = (SAMLObjectBuilder<SubjectConfirmation>) builderFactory
                .getBuilder(SubjectConfirmation.DEFAULT_ELEMENT_NAME);
        this.authnStatementBuilder = (SAMLObjectBuilder<AuthnStatement>) builderFactory
                .getBuilder(AuthnStatement.DEFAULT_ELEMENT_NAME);
        this.subjectConfirmationDataBuilder = (SAMLObjectBuilder<SubjectConfirmationData>) builderFactory
                .getBuilder(SubjectConfirmationData.DEFAULT_ELEMENT_NAME);
        this.authnContextBuilder = (SAMLObjectBuilder<AuthnContext>) builderFactory
                .getBuilder(AuthnContext.DEFAULT_ELEMENT_NAME);
        this.attributeStatementBuilder = (SAMLObjectBuilder<AttributeStatement>) builderFactory
                .getBuilder(AttributeStatement.DEFAULT_ELEMENT_NAME);
        this.attributeBuilder = (SAMLObjectBuilder<Attribute>) builderFactory
                .getBuilder(Attribute.DEFAULT_ELEMENT_NAME);
        this.stringBuilder = builderFactory.getBuilder(XSString.TYPE_NAME);
        this.dateBuilder = builderFactory.getBuilder(XSDateTime.TYPE_NAME);
        this.base64BinaryBuilder = builderFactory.getBuilder(XSBase64Binary.TYPE_NAME);
    }

    public IdentityProviderFlow handleIncomingRequest(
            HttpServletRequest request, HttpServletResponse response)
            throws Exception {
        LOG.debug("handling incoming request");

        BasicSAMLMessageContext<SAMLObject, SAMLObject, SAMLObject> messageContext =
                new BasicSAMLMessageContext<SAMLObject, SAMLObject, SAMLObject>();
        messageContext
                .setInboundMessageTransport(new HttpServletRequestAdapter(
                        request));

        SAMLMessageDecoder decoder = new HTTPPostDecoder();
        decoder.decode(messageContext);

        SAMLObject samlObject = messageContext.getInboundSAMLMessage();
        LOG.debug("SAML object class: " + samlObject.getClass().getName());
        if (!(samlObject instanceof AuthnRequest)) {
            throw new IllegalArgumentException(
                    "expected a SAML2 AuthnRequest document");
        }
        AuthnRequest authnRequest = (AuthnRequest) samlObject;
        String targetUrl = authnRequest.getAssertionConsumerServiceURL();
        LOG.debug("target URL: " + targetUrl);
        setTargetUrl(targetUrl, request);

        String relayState = messageContext.getRelayState();
        setRelayState(relayState, request);

        String inResponseTo = authnRequest.getID();
        setInResponseTo(inResponseTo, request);

        return getAuthenticationFlow();

    }

    @SuppressWarnings("unchecked")
    public ReturnResponse handleReturnResponse(HttpSession httpSession,
                                               String userId,
                                               String givenName, String surName,
                                               Identity identity,
                                               Address address,
                                               byte[] photo,
                                               HttpServletRequest request,
                                               HttpServletResponse response)
            throws Exception {
        LOG.debug("handle return response");
        LOG.debug("userId: " + userId);
        String targetUrl = getTargetUrl(httpSession);
        String relayState = getRelayState(httpSession);
        String inResponseTo = getInResponseTo(httpSession);

        try {
            DefaultBootstrap.bootstrap();
        } catch (ConfigurationException e) {
            throw new ServletException("opensaml config error: "
                    + e.getMessage(), e);
        }

        Response samlResponse = responseBuilder.buildObject();
        DateTime issueInstant = new DateTime();
        samlResponse.setIssueInstant(issueInstant);
        samlResponse.setVersion(SAMLVersion.VERSION_20);
        samlResponse.setDestination(targetUrl);
        String samlResponseId = "saml-response-" + UUID.randomUUID().toString();
        samlResponse.setID(samlResponseId);

        Status status = statusBuilder.buildObject();
        samlResponse.setStatus(status);
        StatusCode statusCode = statusCodeBuilder.buildObject();
        status.setStatusCode(statusCode);
        statusCode.setValue(StatusCode.SUCCESS_URI);

        List<Assertion> assertions = samlResponse.getAssertions();
        Assertion assertion = assertionBuilder.buildObject();
        assertions.add(assertion);
        assertion.setVersion(SAMLVersion.VERSION_20);
        String assertionId = "assertion-" + UUID.randomUUID().toString();
        assertion.setID(assertionId);
        assertion.setIssueInstant(issueInstant);

        Issuer issuer = issuerBuilder.buildObject();
        assertion.setIssuer(issuer);
        issuer.setValue("http://www.e-contract.be/"); // TODO

        Conditions conditions = conditionsBuilder.buildObject();
        assertion.setConditions(conditions);
        DateTime notBefore = issueInstant;
        DateTime notAfter = issueInstant.plusMinutes(5); // TODO: configurable
        conditions.setNotBefore(notBefore);
        conditions.setNotOnOrAfter(notAfter);
        List<AudienceRestriction> audienceRestrictionList = conditions
                .getAudienceRestrictions();
        AudienceRestriction audienceRestriction = audienceRestrictionBuilder
                .buildObject();
        audienceRestrictionList.add(audienceRestriction);
        List<Audience> audiences = audienceRestriction.getAudiences();
        Audience audience = audienceBuilder.buildObject();
        audiences.add(audience);
        audience.setAudienceURI(targetUrl);

        Subject subject = subjectBuilder.buildObject();
        assertion.setSubject(subject);
        NameID nameId = nameIdBuilder.buildObject();
        subject.setNameID(nameId);
        nameId.setValue(userId);
        List<SubjectConfirmation> subjectConfirmations = subject
                .getSubjectConfirmations();
        SubjectConfirmation subjectConfirmation = subjectConfirmationBuilder
                .buildObject();
        subjectConfirmations.add(subjectConfirmation);
        subjectConfirmation.setMethod("urn:oasis:names:tc:SAML:2.0:cm:bearer");
        SubjectConfirmationData subjectConfirmationData = subjectConfirmationDataBuilder
                .buildObject();
        subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);
        subjectConfirmationData.setRecipient(targetUrl);
        subjectConfirmationData.setInResponseTo(inResponseTo);
        subjectConfirmationData.setNotBefore(notBefore);
        subjectConfirmationData.setNotOnOrAfter(notAfter);

        List<AuthnStatement> authnStatements = assertion.getAuthnStatements();
        AuthnStatement authnStatement = authnStatementBuilder.buildObject();
        authnStatements.add(authnStatement);
        authnStatement.setAuthnInstant(issueInstant);
        AuthnContext authnContext = authnContextBuilder.buildObject();
        authnStatement.setAuthnContext(authnContext);

        List<AttributeStatement> attributeStatements = assertion
                .getAttributeStatements();
        AttributeStatement attributeStatement = attributeStatementBuilder
                .buildObject();
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

        ReturnResponse returnResponse = new ReturnResponse(targetUrl);

        HTTPPostEncoder messageEncoder = new HTTPPostEncoder();
        BasicSAMLMessageContext messageContext = new BasicSAMLMessageContext();
        messageContext.setOutboundSAMLMessage(samlResponse);
        messageContext.setRelayState(relayState);

        KeyStore.PrivateKeyEntry idpIdentity = this.configuration.findIdentity();
        if (null != idpIdentity) {
            BasicX509Credential credential = new BasicX509Credential();
            credential.setPrivateKey(idpIdentity.getPrivateKey());
            credential.setEntityCertificate((X509Certificate) idpIdentity.getCertificate());
            messageContext.setOutboundSAMLMessageSigningCredential(credential);
        }
        OutTransport outTransport = new HTTPOutTransport(returnResponse);
        messageContext.setOutboundMessageTransport(outTransport);

        messageEncoder.encode(messageContext);
        return returnResponse;
    }

    private void addAttribute(String attributeName, String attributeValue,
                              AttributeStatement attributeStatement) {

        List<Attribute> attributes = attributeStatement.getAttributes();

        Attribute attribute = attributeBuilder.buildObject();
        attribute.setName(attributeName);
        attributes.add(attribute);

        XSString xmlAttributeValue = stringBuilder.buildObject(
                AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
        xmlAttributeValue.setValue(attributeValue);
        attribute.getAttributeValues().add(xmlAttributeValue);
    }

    private void addAttribute(String attributeName,
                              GregorianCalendar attributeValue,
                              AttributeStatement attributeStatement) {

        List<Attribute> attributes = attributeStatement.getAttributes();

        Attribute attribute = attributeBuilder.buildObject();
        attribute.setName(attributeName);
        attributes.add(attribute);

        XSDateTime xmlAttributeValue = dateBuilder.buildObject(
                AttributeValue.DEFAULT_ELEMENT_NAME, XSDateTime.TYPE_NAME);
        xmlAttributeValue.setValue(new DateTime(attributeValue.getTime()));
        attribute.getAttributeValues().add(xmlAttributeValue);
    }

    private void addAttribute(String attributeName, byte[] attributeValue,
                              AttributeStatement attributeStatement) {

        List<Attribute> attributes = attributeStatement.getAttributes();

        Attribute attribute = attributeBuilder.buildObject();
        attribute.setName(attributeName);
        attributes.add(attribute);

        XSBase64Binary xmlAttributeValue = base64BinaryBuilder.buildObject(
                AttributeValue.DEFAULT_ELEMENT_NAME, XSBase64Binary.TYPE_NAME);
        xmlAttributeValue.setValue(Base64.encodeBytes(attributeValue));
        attribute.getAttributeValues().add(xmlAttributeValue);
    }

    protected abstract IdentityProviderFlow getAuthenticationFlow();
}
