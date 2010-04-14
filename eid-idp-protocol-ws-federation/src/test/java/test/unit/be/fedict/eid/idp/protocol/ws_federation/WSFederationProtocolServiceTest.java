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

package test.unit.be.fedict.eid.idp.protocol.ws_federation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.xml.crypto.Data;
import javax.xml.crypto.NodeSetData;
import javax.xml.crypto.URIDereferencer;
import javax.xml.crypto.URIReference;
import javax.xml.crypto.URIReferenceException;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xml.security.Init;
import org.apache.xml.security.utils.Constants;
import org.apache.xpath.XPathAPI;
import org.easymock.EasyMock;
import org.junit.Before;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import be.fedict.eid.applet.service.Address;
import be.fedict.eid.applet.service.Identity;
import be.fedict.eid.applet.service.signer.KeyInfoKeySelector;
import be.fedict.eid.idp.protocol.ws_federation.WSFederationProtocolService;
import be.fedict.eid.idp.spi.NameValuePair;
import be.fedict.eid.idp.spi.ReturnResponse;

public class WSFederationProtocolServiceTest {

	private static final Log LOG = LogFactory
			.getLog(WSFederationProtocolServiceTest.class);

	@Before
	public void setUp() throws Exception {
		Init.init();
	}

	@Test
	public void testhandleReturnResponse() throws Exception {
		// setup
		WSFederationProtocolService testedInstance = new WSFederationProtocolService();

		HttpSession mockHttpSession = EasyMock.createMock(HttpSession.class);
		Identity identity = new Identity();
		identity.name = "test-name";
		Address address = new Address();
		String authenticatedIdentifier = "test-auth-identifier";
		HttpServletRequest mockRequest = EasyMock
				.createMock(HttpServletRequest.class);
		HttpServletResponse mockResponse = EasyMock
				.createMock(HttpServletResponse.class);

		// expectations
		EasyMock
				.expect(
						mockHttpSession
								.getAttribute(WSFederationProtocolService.WTREALM_SESSION_ATTRIBUTE))
				.andStubReturn("http://return.to.here");
		EasyMock
				.expect(
						mockHttpSession
								.getAttribute(WSFederationProtocolService.WCTX_SESSION_ATTRIBUTE))
				.andStubReturn("some-context-identifier");

		// prepare
		EasyMock.replay(mockHttpSession, mockRequest, mockResponse);

		// operate
		ReturnResponse result = testedInstance.handleReturnResponse(
				mockHttpSession, identity, address, authenticatedIdentifier,
				mockRequest, mockResponse);

		// verify
		EasyMock.verify(mockHttpSession, mockRequest, mockResponse);
		assertEquals("http://return.to.here", result.getActionUrl());
		assertAttribute(result, "wa", "wsignin1.0");
		assertAttribute(result, "wctx", "some-context-identifier");
		String wresult = getAttributeValue(result, "wresult");
		assertNotNull(wresult);
		LOG.debug("wresult: " + wresult);
	}

	// @Test
	public void testSignatureVerification() throws Exception {
		// setup
		InputStream documentInputStream = WSFederationProtocolServiceTest.class
				.getResourceAsStream("/sts-response-message.xml");
		assertNotNull(documentInputStream);

		Document document = loadDocument(documentInputStream);

		NodeList signatureNodeList = document.getElementsByTagNameNS(
				XMLSignature.XMLNS, "Signature");
		assertEquals(1, signatureNodeList.getLength());
		Node signatureNode = signatureNodeList.item(0);

		KeyInfoKeySelector keySelector = new KeyInfoKeySelector();
		DOMValidateContext domValidateContext = new DOMValidateContext(
				keySelector, signatureNode);
		SAMLURIDereferencer dereferencer = new SAMLURIDereferencer(document);
		domValidateContext.setURIDereferencer(dereferencer);

		XMLSignatureFactory xmlSignatureFactory = XMLSignatureFactory
				.getInstance();
		XMLSignature xmlSignature = xmlSignatureFactory
				.unmarshalXMLSignature(domValidateContext);

		// operate
		boolean validity = xmlSignature.validate(domValidateContext);

		// verify
		assertTrue(validity);
	}

	private Document loadDocument(InputStream documentInputStream)
			throws ParserConfigurationException, SAXException, IOException {
		InputSource inputSource = new InputSource(documentInputStream);
		DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory
				.newInstance();
		documentBuilderFactory.setNamespaceAware(true);
		DocumentBuilder documentBuilder = documentBuilderFactory
				.newDocumentBuilder();
		Document document = documentBuilder.parse(inputSource);
		return document;
	}

	private String getAttributeValue(ReturnResponse returnResponse,
			String attributeName) {
		assertNotNull(returnResponse);
		List<NameValuePair> attributes = returnResponse.getAttributes();
		for (NameValuePair attribute : attributes) {
			if (attributeName.equals(attribute.getName())) {
				return attribute.getValue();
			}
		}
		fail("attribute not found: " + attributeName);
		return null;
	}

	private void assertAttribute(ReturnResponse returnResponse,
			String attributeName, String attributeValue) {
		assertNotNull(returnResponse);
		List<NameValuePair> attributes = returnResponse.getAttributes();
		for (NameValuePair attribute : attributes) {
			if (attributeName.equals(attribute.getName())) {
				assertEquals(attributeValue, attribute.getValue());
				return;
			}
		}
		fail("attribute not found: " + attributeName);
	}

	public static class SAMLURIDereferencer implements URIDereferencer {

		private static final Log LOG = LogFactory
				.getLog(SAMLURIDereferencer.class);

		private final Document document;

		public SAMLURIDereferencer(Document document) {
			this.document = document;
		}

		@Override
		public Data dereference(URIReference uriReference,
				XMLCryptoContext context) throws URIReferenceException {
			if (null == uriReference) {
				throw new NullPointerException("URIReference cannot be null");
			}
			if (null == context) {
				throw new NullPointerException("XMLCrytoContext cannot be null");
			}

			String uri = uriReference.getURI();
			try {
				uri = URLDecoder.decode(uri, "UTF-8");
			} catch (UnsupportedEncodingException e) {
				LOG.warn("could not URL decode the uri: " + uri);
			}
			LOG.debug("dereference: " + uri);
			String assertionId = uri.substring(1);
			Element nsElement = document.createElement("ns");
			nsElement.setAttributeNS(Constants.NamespaceSpecNS, "xmlns:saml",
					"urn:oasis:names:tc:SAML:1.0:assertion");
			Node assertionNode;
			try {
				assertionNode = XPathAPI.selectSingleNode(document,
						"//saml:Assertion[@AssertionID='" + assertionId + "']",
						nsElement);
			} catch (TransformerException e) {
				throw new URIReferenceException("XPath error: "
						+ e.getMessage(), e);
			}
			if (null == assertionNode) {
				throw new URIReferenceException("SAML Assertion not found");
			}
			DOMNodeSetData nodeSetData = new DOMNodeSetData(assertionNode);
			LOG.debug("returning node set data...");
			return nodeSetData;
		}
	}

	private static class DOMNodeSetData implements NodeSetData {

		private final Node node;

		public DOMNodeSetData(Node node) {
			this.node = node;
		}

		@Override
		public Iterator iterator() {
			return Collections.singletonList(this.node).iterator();
		}
	}
}
