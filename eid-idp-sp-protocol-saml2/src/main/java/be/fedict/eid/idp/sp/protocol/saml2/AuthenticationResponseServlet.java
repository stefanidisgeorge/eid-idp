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

package be.fedict.eid.idp.sp.protocol.saml2;

import java.io.IOException;
import java.util.List;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
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
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.Subject;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.security.SecurityException;

public class AuthenticationResponseServlet extends HttpServlet {

	private static final long serialVersionUID = 1L;

	private static final Log LOG = LogFactory
			.getLog(AuthenticationResponseServlet.class);

	private String identifierSessionAttribute;

	private String redirectPage;

	private boolean parametersFromRequest;

	@Override
	public void init(ServletConfig config) throws ServletException {
		String parametersFromRequest = config
				.getInitParameter("ParametersFromRequest");
		if (null != parametersFromRequest) {
			this.parametersFromRequest = Boolean
					.parseBoolean(parametersFromRequest);
		}
		if (false == this.parametersFromRequest) {
			this.identifierSessionAttribute = config
					.getInitParameter("IdentifierSessionAttribute");
			if (null == this.identifierSessionAttribute) {
				throw new ServletException(
						"missing IdentifierSessionAttribute init-param");
			}
			this.redirectPage = config.getInitParameter("RedirectPage");
			if (null == this.redirectPage) {
				throw new ServletException("RedirectPage init-param required");
			}
		}
	}

	@Override
	protected void doPost(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {
		LOG.debug("doPost");

		String identifierSessionAttribute;
		String redirectPage;
		if (this.parametersFromRequest) {
			LOG
					.warn("Retrieving parameters from request. For testing purposes only!!!");
			identifierSessionAttribute = request
					.getParameter("IdentifierSessionAttribute");
			if (null == identifierSessionAttribute) {
				throw new ServletException(
						"IdentifierSessionAttribute parameter missing");
			}
			redirectPage = request.getParameter("RedirectPage");
			if (null == redirectPage) {
				throw new ServletException("RedirectPage parameter missing");
			}
		} else {
			identifierSessionAttribute = this.identifierSessionAttribute;
			redirectPage = this.redirectPage;
		}

		HttpSession httpSession = request.getSession();
		httpSession.removeAttribute(this.identifierSessionAttribute);

		try {
			DefaultBootstrap.bootstrap();
		} catch (ConfigurationException e) {
			throw new ServletException("OpenSAML configuration exception");
		}

		BasicSAMLMessageContext<SAMLObject, SAMLObject, SAMLObject> messageContext = new BasicSAMLMessageContext<SAMLObject, SAMLObject, SAMLObject>();
		messageContext
				.setInboundMessageTransport(new HttpServletRequestAdapter(
						request));

		SAMLMessageDecoder decoder = new HTTPPostDecoder();
		try {
			decoder.decode(messageContext);
		} catch (MessageDecodingException e) {
			throw new ServletException("OpenSAML message decoding error");
		} catch (SecurityException e) {
			LOG.error("OpenSAML security error: " + e.getMessage(), e);
			throw new ServletException("OpenSAML security error");
		}

		SAMLObject samlObject = messageContext.getInboundSAMLMessage();
		LOG.debug("SAML object class: " + samlObject.getClass().getName());
		if (false == samlObject instanceof Response) {
			throw new IllegalArgumentException(
					"expected a SAML2 Response document");
		}
		Response samlResponse = (Response) samlObject;

		Status status = samlResponse.getStatus();
		StatusCode statusCode = status.getStatusCode();
		String statusValue = statusCode.getValue();
		if (false == StatusCode.SUCCESS_URI.equals(statusValue)) {
			throw new ServletException("no successful SAML response");
		}

		List<Assertion> assertions = samlResponse.getAssertions();
		if (assertions.isEmpty()) {
			throw new ServletException("missing SAML assertions");
		}

		Assertion assertion = assertions.get(0);
		List<AuthnStatement> authnStatements = assertion.getAuthnStatements();
		if (authnStatements.isEmpty()) {
			throw new ServletException("missing SAML authn statement");
		}

		Subject subject = assertion.getSubject();
		NameID nameId = subject.getNameID();
		String identifier = nameId.getValue();
		httpSession.setAttribute(identifierSessionAttribute, identifier);
		response.sendRedirect(request.getContextPath() + redirectPage);
	}
}
