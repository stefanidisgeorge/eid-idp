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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.common.binding.decoding.SAMLMessageDecoder;
import org.opensaml.saml2.binding.decoding.HTTPPostDecoder;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;

import be.fedict.eid.applet.service.Address;
import be.fedict.eid.applet.service.Identity;
import be.fedict.eid.idp.spi.IdentityProviderProtocolService;

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

	private void setTargetUrl(String targetUrl, HttpServletRequest request) {
		HttpSession httpSession = request.getSession();
		httpSession.setAttribute(TARGET_URL_SESSION_ATTRIBUTE, targetUrl);
	}

	private String getTargetUrl(HttpSession httpSession) {
		String targetUrl = (String) httpSession
				.getAttribute(TARGET_URL_SESSION_ATTRIBUTE);
		return targetUrl;
	}

	public IdentityProviderFlow handleIncomingRequest(HttpServletRequest request)
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

		return IdentityProviderFlow.AUTHENTICATION_WITH_IDENTIFICATION;
	}

	public ReturnResponse handleReturnResponse(HttpSession httpSession,
			Identity identity, Address address, String authenticatedIdentifier,
			HttpServletResponse response) throws Exception {
		LOG.debug("handle return response");
		LOG.debug("authenticated identifier: " + authenticatedIdentifier);
		// TODO
		return null;
	}
}
