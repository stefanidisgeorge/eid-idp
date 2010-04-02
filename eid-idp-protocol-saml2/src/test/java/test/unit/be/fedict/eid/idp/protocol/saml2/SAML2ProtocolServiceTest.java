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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.UUID;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.velocity.app.VelocityEngine;
import org.apache.velocity.runtime.RuntimeConstants;
import org.apache.xpath.XPathAPI;
import org.easymock.EasyMock;
import org.joda.time.DateTime;
import org.junit.Test;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.saml2.binding.encoding.HTTPPostEncoder;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.ws.transport.OutTransport;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.tidy.Tidy;

import be.fedict.eid.applet.service.Address;
import be.fedict.eid.applet.service.Gender;
import be.fedict.eid.applet.service.Identity;
import be.fedict.eid.idp.protocol.saml2.SAML2ProtocolService;
import be.fedict.eid.idp.spi.NameValuePair;
import be.fedict.eid.idp.spi.ReturnResponse;

public class SAML2ProtocolServiceTest {

	private static final Log LOG = LogFactory
			.getLog(SAML2ProtocolServiceTest.class);

	@Test
	public void testOpenSaml2Spike() throws Exception {
		/*
		 * Setup
		 */
		DefaultBootstrap.bootstrap();

		XMLObjectBuilderFactory builderFactory = Configuration
				.getBuilderFactory();
		assertNotNull(builderFactory);

		SAMLObjectBuilder<AuthnRequest> requestBuilder = (SAMLObjectBuilder<AuthnRequest>) builderFactory
				.getBuilder(AuthnRequest.DEFAULT_ELEMENT_NAME);
		assertNotNull(requestBuilder);
		AuthnRequest samlMessage = requestBuilder.buildObject();
		samlMessage.setID(UUID.randomUUID().toString());
		samlMessage.setVersion(SAMLVersion.VERSION_20);
		samlMessage.setIssueInstant(new DateTime(0));

		SAMLObjectBuilder<Endpoint> endpointBuilder = (SAMLObjectBuilder<Endpoint>) builderFactory
				.getBuilder(AssertionConsumerService.DEFAULT_ELEMENT_NAME);
		Endpoint samlEndpoint = endpointBuilder.buildObject();
		samlEndpoint.setLocation("http://idp.be");
		samlEndpoint.setResponseLocation("http://sp.be/response");

		HttpServletResponse mockHttpServletResponse = EasyMock
				.createMock(HttpServletResponse.class);
		OutTransport outTransport = new HttpServletResponseAdapter(
				mockHttpServletResponse, true);

		BasicSAMLMessageContext messageContext = new BasicSAMLMessageContext();
		messageContext.setOutboundMessageTransport(outTransport);
		messageContext.setPeerEntityEndpoint(samlEndpoint);
		messageContext.setOutboundSAMLMessage(samlMessage);

		VelocityEngine velocityEngine = new VelocityEngine();
		velocityEngine.setProperty(RuntimeConstants.RESOURCE_LOADER,
				"classpath");
		velocityEngine
				.setProperty("classpath.resource.loader.class",
						"org.apache.velocity.runtime.resource.loader.ClasspathResourceLoader");
		velocityEngine.init();
		HTTPPostEncoder encoder = new HTTPPostEncoder(velocityEngine,
				"/templates/saml2-post-binding.vm");

		/*
		 * Expectations
		 */
		mockHttpServletResponse
				.setHeader("Cache-control", "no-cache, no-store");
		mockHttpServletResponse.setHeader("Pragma", "no-cache");
		mockHttpServletResponse.setCharacterEncoding("UTF-8");
		mockHttpServletResponse.setContentType("text/html");
		mockHttpServletResponse.setHeader("Content-Type", "text/html");
		final ByteArrayOutputStream baos = new ByteArrayOutputStream();
		ServletOutputStream mockServletOutputStream = new ServletOutputStream() {
			@Override
			public void write(int b) throws IOException {
				baos.write(b);
			}
		};
		EasyMock.expect(mockHttpServletResponse.getOutputStream()).andReturn(
				mockServletOutputStream);

		/*
		 * Perform
		 */
		EasyMock.replay(mockHttpServletResponse);
		encoder.encode(messageContext);

		/*
		 * Verify
		 */
		EasyMock.verify(mockHttpServletResponse);
		ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(
				baos.toByteArray());
		LOG.debug("SAML2 Request Browser POST: " + baos.toString());
		Tidy tidy = new Tidy();
		Document document = tidy.parseDOM(byteArrayInputStream, null);

		Node actionNode = XPathAPI.selectSingleNode(document,
				"//form[@action='http://idp.be']");
		assertNotNull(actionNode);
	}

	@Test
	public void testHandleIncomingRequest() throws Exception {
		// setup
		SAML2ProtocolService saml2ProtocolService = new SAML2ProtocolService();
		HttpServletRequest mockHttpServletRequest = EasyMock
				.createMock(HttpServletRequest.class);

		InputStream samlRequestInputStream = SAML2ProtocolServiceTest.class
				.getResourceAsStream("/saml-request.xml");
		byte[] samlRequest = IOUtils.toByteArray(samlRequestInputStream);
		byte[] encodedSamlRequest = Base64.encodeBase64(samlRequest);

		// expectations
		EasyMock.expect(mockHttpServletRequest.getMethod()).andReturn("POST");
		EasyMock.expect(mockHttpServletRequest.getParameter("RelayState"))
				.andStubReturn(null);
		EasyMock.expect(mockHttpServletRequest.getParameter("SAMLRequest"))
				.andReturn(new String(encodedSamlRequest));
		EasyMock.expect(mockHttpServletRequest.getRequestURL()).andReturn(
				new StringBuffer("http://idp.be"));

		HttpSession mockHttpSession = EasyMock.createMock(HttpSession.class);
		EasyMock.expect(mockHttpServletRequest.getSession()).andStubReturn(
				mockHttpSession);
		mockHttpSession.setAttribute(SAML2ProtocolService.class.getName()
				+ ".TargetUrl", "http://sp.be/response");
		mockHttpSession.setAttribute(SAML2ProtocolService.class.getName()
				+ ".RelayState", null);

		// prepare
		EasyMock.replay(mockHttpServletRequest, mockHttpSession);

		// operate
		saml2ProtocolService
				.handleIncomingRequest(mockHttpServletRequest, null);

		// verify
		EasyMock.verify(mockHttpServletRequest, mockHttpSession);
	}

	@Test
	public void testHandleReturnResponse() throws Exception {
		// setup
		SAML2ProtocolService saml2ProtocolService = new SAML2ProtocolService();

		HttpSession httpSession;
		Address address = new Address();
		String authenticatedIdentifier = "authn-id";
		HttpServletResponse response;
		Identity identity = new Identity();
		identity.name = "test-name";
		identity.firstName = "test-first-name";
		identity.gender = Gender.MALE;
		HttpSession mockHttpSession = EasyMock.createMock(HttpSession.class);
		HttpServletResponse mockHttpServletResponse = EasyMock
				.createMock(HttpServletResponse.class);

		// expectations
		EasyMock
				.expect(
						mockHttpSession
								.getAttribute(SAML2ProtocolService.TARGET_URL_SESSION_ATTRIBUTE))
				.andStubReturn("target-url");
		EasyMock
				.expect(
						mockHttpSession
								.getAttribute(SAML2ProtocolService.RELAY_STATE_SESSION_ATTRIBUTE))
				.andStubReturn("relay-state");

		// prepare
		EasyMock.replay(mockHttpSession);

		// operate
		ReturnResponse returnResponse = saml2ProtocolService
				.handleReturnResponse(mockHttpSession, identity, address,
						authenticatedIdentifier, mockHttpServletResponse);

		// verify
		EasyMock.verify(mockHttpSession);
		assertNotNull(returnResponse);
		assertEquals("target-url", returnResponse.getActionUrl());
		List<NameValuePair> attributes = returnResponse.getAttributes();
		assertNotNull(attributes);
		NameValuePair relayStateAttribute = null;
		NameValuePair samlResponseAttribute = null;
		for (NameValuePair attribute : attributes) {
			if ("RelayState".equals(attribute.getName())) {
				relayStateAttribute = attribute;
				continue;
			}
			if ("SAMLResponse".equals(attribute.getName())) {
				samlResponseAttribute = attribute;
				continue;
			}
		}
		assertNotNull(relayStateAttribute);
		assertEquals("relay-state", relayStateAttribute.getValue());
		assertNotNull("no SAMLResponse attribute", samlResponseAttribute);
		String encodedSamlResponse = samlResponseAttribute.getValue();
		assertNotNull(encodedSamlResponse);
		String samlResponse = new String(Base64
				.decodeBase64(encodedSamlResponse));
		LOG.debug("SAML response: " + samlResponse);
		// TODO
	}
}