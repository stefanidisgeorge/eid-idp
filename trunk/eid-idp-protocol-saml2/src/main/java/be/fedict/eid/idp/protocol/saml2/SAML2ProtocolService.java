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

import java.util.List;
import java.util.UUID;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

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
import org.opensaml.common.binding.encoding.SAMLMessageEncoder;
import org.opensaml.saml2.binding.decoding.HTTPPostDecoder;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AttributeValue;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.Subject;
import org.opensaml.ws.transport.OutTransport;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.schema.XSString;

import be.fedict.eid.applet.service.Address;
import be.fedict.eid.applet.service.Identity;
import be.fedict.eid.idp.spi.IdentityProviderFlow;
import be.fedict.eid.idp.spi.IdentityProviderProtocolService;
import be.fedict.eid.idp.spi.ReturnResponse;

/**
 * SAML2 Browser POST Profile protocol service.
 * 
 * @author Frank Cornelis
 * 
 */
public class SAML2ProtocolService implements IdentityProviderProtocolService {

	private static final Log LOG = LogFactory
			.getLog(SAML2ProtocolService.class);

	public static final String TARGET_URL_SESSION_ATTRIBUTE = SAML2ProtocolService.class
			.getName()
			+ ".TargetUrl";

	public static final String RELAY_STATE_SESSION_ATTRIBUTE = SAML2ProtocolService.class
			.getName()
			+ ".RelayState";

	private void setTargetUrl(String targetUrl, HttpServletRequest request) {
		HttpSession httpSession = request.getSession();
		httpSession.setAttribute(TARGET_URL_SESSION_ATTRIBUTE, targetUrl);
	}

	private String getTargetUrl(HttpSession httpSession) {
		String targetUrl = (String) httpSession
				.getAttribute(TARGET_URL_SESSION_ATTRIBUTE);
		return targetUrl;
	}

	private void setRelayState(String relayState, HttpServletRequest request) {
		HttpSession httpSession = request.getSession();
		httpSession.setAttribute(RELAY_STATE_SESSION_ATTRIBUTE, relayState);
	}

	private String getRelayState(HttpSession httpSession) {
		String relayState = (String) httpSession
				.getAttribute(RELAY_STATE_SESSION_ATTRIBUTE);
		return relayState;
	}

	public void init(ServletContext servletContext) {
		LOG.debug("init");
	}

	public IdentityProviderFlow handleIncomingRequest(
			HttpServletRequest request, HttpServletResponse response)
			throws Exception {
		LOG.debug("handling incoming request");
		DefaultBootstrap.bootstrap();

		BasicSAMLMessageContext<SAMLObject, SAMLObject, SAMLObject> messageContext = new BasicSAMLMessageContext<SAMLObject, SAMLObject, SAMLObject>();
		messageContext
				.setInboundMessageTransport(new HttpServletRequestAdapter(
						request));

		SAMLMessageDecoder decoder = new HTTPPostDecoder();
		decoder.decode(messageContext);

		SAMLObject samlObject = messageContext.getInboundSAMLMessage();
		LOG.debug("SAML object class: " + samlObject.getClass().getName());
		if (false == samlObject instanceof AuthnRequest) {
			throw new IllegalArgumentException(
					"expected a SAML2 AuthnRequest document");
		}
		AuthnRequest authnRequest = (AuthnRequest) samlObject;
		String targetUrl = authnRequest.getAssertionConsumerServiceURL();
		LOG.debug("target URL: " + targetUrl);
		setTargetUrl(targetUrl, request);

		String relayState = messageContext.getRelayState();
		setRelayState(relayState, request);

		return IdentityProviderFlow.AUTHENTICATION_WITH_IDENTIFICATION;
	}

	public ReturnResponse handleReturnResponse(HttpSession httpSession,
			Identity identity, Address address, String authenticatedIdentifier,
			HttpServletRequest request, HttpServletResponse response)
			throws Exception {
		LOG.debug("handle return response");
		LOG.debug("authenticated identifier: " + authenticatedIdentifier);
		String targetUrl = getTargetUrl(httpSession);
		String relayState = getRelayState(httpSession);

		try {
			DefaultBootstrap.bootstrap();
		} catch (ConfigurationException e) {
			throw new ServletException("opensaml config error: "
					+ e.getMessage(), e);
		}

		XMLObjectBuilderFactory builderFactory = Configuration
				.getBuilderFactory();

		SAMLObjectBuilder<Response> responseBuilder = (SAMLObjectBuilder<Response>) builderFactory
				.getBuilder(Response.DEFAULT_ELEMENT_NAME);
		Response samlResponse = responseBuilder.buildObject();
		DateTime issueInstant = new DateTime();
		samlResponse.setIssueInstant(issueInstant);
		samlResponse.setVersion(SAMLVersion.VERSION_20);
		String samlResponseId = "saml-response-" + UUID.randomUUID().toString();
		samlResponse.setID(samlResponseId);

		SAMLObjectBuilder<Status> statusBuilder = (SAMLObjectBuilder<Status>) builderFactory
				.getBuilder(Status.DEFAULT_ELEMENT_NAME);
		Status status = statusBuilder.buildObject();
		samlResponse.setStatus(status);
		SAMLObjectBuilder<StatusCode> statusCodeBuilder = (SAMLObjectBuilder<StatusCode>) builderFactory
				.getBuilder(StatusCode.DEFAULT_ELEMENT_NAME);
		StatusCode statusCode = statusCodeBuilder.buildObject();
		status.setStatusCode(statusCode);
		statusCode.setValue(StatusCode.SUCCESS_URI);

		List<Assertion> assertions = samlResponse.getAssertions();
		SAMLObjectBuilder<Assertion> assertionBuilder = (SAMLObjectBuilder<Assertion>) builderFactory
				.getBuilder(Assertion.DEFAULT_ELEMENT_NAME);
		Assertion assertion = assertionBuilder.buildObject();
		assertions.add(assertion);
		assertion.setVersion(SAMLVersion.VERSION_20);
		String assertionId = "assertion-" + UUID.randomUUID().toString();
		assertion.setID(assertionId);
		assertion.setIssueInstant(issueInstant);
		SAMLObjectBuilder<Issuer> issuerBuilder = (SAMLObjectBuilder<Issuer>) builderFactory
				.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
		Issuer issuer = issuerBuilder.buildObject();
		assertion.setIssuer(issuer);
		issuer.setValue("http://www.e-contract.be/"); // TODO

		SAMLObjectBuilder<Subject> subjectBuilder = (SAMLObjectBuilder<Subject>) builderFactory
				.getBuilder(Subject.DEFAULT_ELEMENT_NAME);
		Subject subject = subjectBuilder.buildObject();
		assertion.setSubject(subject);
		SAMLObjectBuilder<NameID> nameIdBuilder = (SAMLObjectBuilder<NameID>) builderFactory
				.getBuilder(NameID.DEFAULT_ELEMENT_NAME);
		NameID nameId = nameIdBuilder.buildObject();
		subject.setNameID(nameId);
		nameId.setValue(authenticatedIdentifier);

		List<AuthnStatement> authnStatements = assertion.getAuthnStatements();
		SAMLObjectBuilder<AuthnStatement> authnStatementBuilder = (SAMLObjectBuilder<AuthnStatement>) builderFactory
				.getBuilder(AuthnStatement.DEFAULT_ELEMENT_NAME);
		AuthnStatement authnStatement = authnStatementBuilder.buildObject();
		authnStatements.add(authnStatement);
		authnStatement.setAuthnInstant(issueInstant);
		SAMLObjectBuilder<AuthnContext> authnContextBuilder = (SAMLObjectBuilder<AuthnContext>) builderFactory
				.getBuilder(AuthnContext.DEFAULT_ELEMENT_NAME);
		AuthnContext authnContext = authnContextBuilder.buildObject();
		authnStatement.setAuthnContext(authnContext);

		List<AttributeStatement> attributeStatements = assertion
				.getAttributeStatements();
		SAMLObjectBuilder<AttributeStatement> attributeStatementBuilder = (SAMLObjectBuilder<AttributeStatement>) builderFactory
				.getBuilder(AttributeStatement.DEFAULT_ELEMENT_NAME);
		AttributeStatement attributeStatement = attributeStatementBuilder
				.buildObject();
		attributeStatements.add(attributeStatement);
		addAttribute("urn:be:fedict:eid:idp:name", identity.getName(),
				builderFactory, attributeStatement);
		addAttribute("urn:be:fedict:eid:idp:firstName",
				identity.getFirstName(), builderFactory, attributeStatement);
		addAttribute("urn:be:fedict:eid:idp:gender", identity.getGender()
				.name(), builderFactory, attributeStatement);

		ReturnResponse returnResponse = new ReturnResponse(targetUrl);

		SAMLMessageEncoder messageEncoder = new HTTPPostEncoder();
		BasicSAMLMessageContext messageContext = new BasicSAMLMessageContext();
		messageContext.setOutboundSAMLMessage(samlResponse);
		messageContext.setRelayState(relayState);
		OutTransport outTransport = new HTTPOutTransport(returnResponse);
		messageContext.setOutboundMessageTransport(outTransport);

		messageEncoder.encode(messageContext);
		return returnResponse;
	}

	private void addAttribute(String attributeName, String attributeValue,
			XMLObjectBuilderFactory builderFactory,
			AttributeStatement attributeStatement) {
		List<Attribute> attributes = attributeStatement.getAttributes();

		SAMLObjectBuilder<Attribute> attributeBuilder = (SAMLObjectBuilder<Attribute>) builderFactory
				.getBuilder(Attribute.DEFAULT_ELEMENT_NAME);
		Attribute nameAttribute = attributeBuilder.buildObject();

		attributes.add(nameAttribute);

		nameAttribute.setName(attributeName);
		XMLObjectBuilder<XSString> stringBuilder = builderFactory
				.getBuilder(XSString.TYPE_NAME);
		XSString nameAttributeValue = (XSString) stringBuilder.buildObject(
				AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
		nameAttributeValue.setValue(attributeValue);
		nameAttribute.getAttributeValues().add(nameAttributeValue);
	}
}
