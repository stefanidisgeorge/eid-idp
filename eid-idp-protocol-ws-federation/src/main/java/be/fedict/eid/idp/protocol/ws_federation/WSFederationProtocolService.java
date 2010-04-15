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

import java.io.ByteArrayOutputStream;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.UUID;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;

import oasis.names.tc.saml._2_0.assertion.AssertionType;
import oasis.names.tc.saml._2_0.assertion.AttributeStatementType;
import oasis.names.tc.saml._2_0.assertion.AttributeType;
import oasis.names.tc.saml._2_0.assertion.NameIDType;
import oasis.names.tc.saml._2_0.assertion.SubjectConfirmationType;
import oasis.names.tc.saml._2_0.assertion.SubjectType;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;
import org.oasis_open.docs.ws_sx.ws_trust._200512.ObjectFactory;
import org.oasis_open.docs.ws_sx.ws_trust._200512.RequestSecurityTokenResponseCollectionType;
import org.oasis_open.docs.ws_sx.ws_trust._200512.RequestSecurityTokenResponseType;
import org.oasis_open.docs.ws_sx.ws_trust._200512.RequestedSecurityTokenType;

import be.fedict.eid.applet.service.Address;
import be.fedict.eid.applet.service.Identity;
import be.fedict.eid.idp.spi.IdentityProviderConfiguration;
import be.fedict.eid.idp.spi.IdentityProviderFlow;
import be.fedict.eid.idp.spi.IdentityProviderProtocolService;
import be.fedict.eid.idp.spi.ReturnResponse;

/**
 * WS-Federation Web (Passive) Requestors. We could use OpenAM (OpenSS0), but
 * then again they're also just doing a wrapping around the JAXB classes.
 * 
 * @author Frank Cornelis
 * 
 */
public class WSFederationProtocolService implements
		IdentityProviderProtocolService {

	private static final Log LOG = LogFactory
			.getLog(WSFederationProtocolService.class);

	public static final String WCTX_SESSION_ATTRIBUTE = WSFederationProtocolService.class
			.getName()
			+ ".wctx";

	public static final String WTREALM_SESSION_ATTRIBUTE = WSFederationProtocolService.class
			.getName()
			+ ".wtrealm";

	private void storeWCtx(String wctx, HttpServletRequest request) {
		HttpSession httpSession = request.getSession();
		httpSession.setAttribute(WCTX_SESSION_ATTRIBUTE, wctx);
	}

	private String retrieveWctx(HttpSession httpSession) {
		String wctx = (String) httpSession.getAttribute(WCTX_SESSION_ATTRIBUTE);
		return wctx;
	}

	private void storeWtrealm(String wtrealm, HttpServletRequest request) {
		HttpSession httpSession = request.getSession();
		httpSession.setAttribute(WTREALM_SESSION_ATTRIBUTE, wtrealm);
	}

	private String retrieveWtrealm(HttpSession httpSession) {
		String wtrealm = (String) httpSession
				.getAttribute(WTREALM_SESSION_ATTRIBUTE);
		return wtrealm;
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
		if (false == "wsignin1.0".equals(wa)) {
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
		return IdentityProviderFlow.AUTHENTICATION_WITH_IDENTIFICATION;
	}

	@Override
	public ReturnResponse handleReturnResponse(HttpSession httpSession,
			Identity identity, Address address, String authenticatedIdentifier,
			HttpServletRequest request, HttpServletResponse response)
			throws Exception {
		LOG.debug("handleReturnResponse");
		String wtrealm = retrieveWtrealm(httpSession);
		ReturnResponse returnResponse = new ReturnResponse(wtrealm);
		returnResponse.addAttribute("wa", "wsignin1.0");
		String wctx = retrieveWctx(httpSession);
		returnResponse.addAttribute("wctx", wctx);
		String wresult = getWResult(wctx, identity, authenticatedIdentifier);
		returnResponse.addAttribute("wresult", wresult);
		return returnResponse;
	}

	private String getWResult(String wctx, Identity identity,
			String authenticatedIdentifier) throws JAXBException,
			DatatypeConfigurationException {
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
		assertion.setID("saml-" + UUID.randomUUID().toString());
		DatatypeFactory datatypeFactory = DatatypeFactory.newInstance();
		DateTime issueInstantDateTime = new DateTime();
		GregorianCalendar issueInstantCalendar = issueInstantDateTime
				.toGregorianCalendar();
		assertion.setIssueInstant(datatypeFactory
				.newXMLGregorianCalendar(issueInstantCalendar));
		NameIDType issuer = samlObjectFactory.createNameIDType();
		issuer.setValue("eID IdP");
		assertion.setIssuer(issuer);

		SubjectType subject = samlObjectFactory.createSubjectType();
		assertion.setSubject(subject);
		NameIDType nameId = samlObjectFactory.createNameIDType();
		nameId.setValue(authenticatedIdentifier);
		subject.getContent().add(samlObjectFactory.createNameID(nameId));

		SubjectConfirmationType subjectConfirmation = samlObjectFactory
				.createSubjectConfirmationType();
		subject.getContent().add(
				samlObjectFactory
						.createSubjectConfirmation(subjectConfirmation));
		subjectConfirmation.setMethod("urn:oasis:names:tc:SAML:2.0:cm:bearer");

		List<Object> attributes = attributeStatement
				.getAttributeOrEncryptedAttribute();
		AttributeType nameAttribute = samlObjectFactory.createAttributeType();
		attributes.add(nameAttribute);
		nameAttribute
				.setName("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name");
		nameAttribute.getAttributeValue().add(identity.getName());

		JAXBContext context = JAXBContext.newInstance(ObjectFactory.class,
				oasis.names.tc.saml._2_0.assertion.ObjectFactory.class);
		Marshaller marshaller = context.createMarshaller();
		marshaller.setProperty("com.sun.xml.bind.namespacePrefixMapper",
				new WSFederationNamespacePrefixMapper());
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		marshaller
				.marshal(
						trustObjectFactory
								.createRequestSecurityTokenResponseCollection(requestSecurityTokenResponseCollection),
						outputStream);

		return new String(outputStream.toByteArray());
	}

	@Override
	public void init(ServletContext servletContext,
			IdentityProviderConfiguration configuration) {
		LOG.debug("init");
	}
}
