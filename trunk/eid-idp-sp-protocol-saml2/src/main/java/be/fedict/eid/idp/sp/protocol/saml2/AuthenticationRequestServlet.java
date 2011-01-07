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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.velocity.app.VelocityEngine;
import org.apache.velocity.runtime.RuntimeConstants;
import org.apache.velocity.runtime.log.Log4JLogChute;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.binding.encoding.HTTPPostEncoder;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.transport.OutTransport;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObjectBuilderFactory;

import be.fedict.eid.idp.sp.protocol.saml2.spi.AuthenticationRequestService;

import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.UUID;

public class AuthenticationRequestServlet extends HttpServlet {

	private static final long serialVersionUID = 1L;

	private static final Log LOG = LogFactory
			.getLog(AuthenticationRequestServlet.class);

	private String idpDestination;

	private String spDestination;

	private boolean parametersFromRequest;

	private String authenticationRequestService;

	@Override
	public void init(ServletConfig config) throws ServletException {
		String parametersFromRequest = config
				.getInitParameter("ParametersFromRequest");
		if (null != parametersFromRequest) {
			this.parametersFromRequest = Boolean
					.parseBoolean(parametersFromRequest);
		}
		if (!this.parametersFromRequest) {
			this.idpDestination = config.getInitParameter("IdPDestination");
			this.authenticationRequestService = config
					.getInitParameter("AuthenticationRequestService");
			if (null == this.idpDestination
					&& null == this.authenticationRequestService) {
				throw new ServletException(
						"need to provide either IdPDestination or AuthenticationRequestService init-params");
			}

			this.spDestination = getRequiredInitParameter("SPDestination",
					config);
		} else {
			LOG.warn("ParametersFromRequest should not be used for production configurations");
		}
	}

	private String getRequiredInitParameter(String parameterName,
			ServletConfig config) throws ServletException {
		String value = config.getInitParameter(parameterName);
		if (null == value) {
			throw new ServletException(parameterName
					+ " init-param is required");
		}
		return value;
	}

	@SuppressWarnings("unchecked")
	@Override
	protected void doGet(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {
		LOG.debug("doGet");

		String idpDestination;
		String spDestination;
		if (this.parametersFromRequest) {
			LOG.warn("Retrieving parameters from the request. Only use for debugging!");
			idpDestination = request.getParameter("IdPDestination");
			if (null == idpDestination) {
				throw new ServletException("IdPDestination parameter required");
			}
			spDestination = request.getParameter("SPDestination");
			if (null == spDestination) {
				throw new ServletException("SPDestination parameter required");
			}
		} else {
			if (null != this.authenticationRequestService) {
				AuthenticationRequestService service;
				try {
					InitialContext initialContext = new InitialContext();
					service = (AuthenticationRequestService) initialContext
							.lookup(this.authenticationRequestService);
				} catch (NamingException e) {
					throw new ServletException(
							"error locating AuthenticationRequestService: "
									+ e.getMessage(), e);
				}
				idpDestination = service.getIdPDestination();
			} else {
				idpDestination = this.idpDestination;
			}
			spDestination = this.spDestination;
		}

		try {
			DefaultBootstrap.bootstrap();
		} catch (ConfigurationException e) {
			throw new ServletException("opensaml config error: "
					+ e.getMessage(), e);
		}

		XMLObjectBuilderFactory builderFactory = Configuration
				.getBuilderFactory();

		SAMLObjectBuilder<AuthnRequest> requestBuilder = (SAMLObjectBuilder<AuthnRequest>) builderFactory
				.getBuilder(AuthnRequest.DEFAULT_ELEMENT_NAME);
		AuthnRequest authnRequest = requestBuilder.buildObject();
		authnRequest.setID("authn-request-" + UUID.randomUUID().toString());
		authnRequest.setVersion(SAMLVersion.VERSION_20);
		authnRequest.setIssueInstant(new DateTime(0));
		authnRequest.setDestination(idpDestination);
		authnRequest.setAssertionConsumerServiceURL(spDestination);
		authnRequest.setForceAuthn(true);
		authnRequest.setProtocolBinding(SAMLConstants.SAML2_POST_BINDING_URI);

		SAMLObjectBuilder<Issuer> issuerBuilder = (SAMLObjectBuilder<Issuer>) builderFactory
				.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
		Issuer issuer = issuerBuilder.buildObject();
		issuer.setValue(spDestination);
		authnRequest.setIssuer(issuer);

		SAMLObjectBuilder<Endpoint> endpointBuilder = (SAMLObjectBuilder<Endpoint>) builderFactory
				.getBuilder(AssertionConsumerService.DEFAULT_ELEMENT_NAME);
		Endpoint samlEndpoint = endpointBuilder.buildObject();
		samlEndpoint.setLocation(idpDestination);
		samlEndpoint.setResponseLocation(spDestination);

		OutTransport outTransport = new HttpServletResponseAdapter(response,
				true);

		BasicSAMLMessageContext messageContext = new BasicSAMLMessageContext();
		messageContext.setOutboundMessageTransport(outTransport);
		messageContext.setPeerEntityEndpoint(samlEndpoint);
		messageContext.setOutboundSAMLMessage(authnRequest);

		VelocityEngine velocityEngine = new VelocityEngine();
		velocityEngine.setProperty(RuntimeConstants.RESOURCE_LOADER,
				"classpath");
		velocityEngine
				.setProperty("classpath.resource.loader.class",
						"org.apache.velocity.runtime.resource.loader.ClasspathResourceLoader");
		velocityEngine.setProperty(
				RuntimeConstants.RUNTIME_LOG_LOGSYSTEM_CLASS,
				Log4JLogChute.class.getName());
		try {
			velocityEngine.init();
		} catch (Exception e) {
			throw new ServletException("velocity engine init error: "
					+ e.getMessage(), e);
		}
		HTTPPostEncoder encoder = new HTTPPostEncoder(velocityEngine,
				"/templates/saml2-post-binding.vm");
		try {
			encoder.encode(messageContext);
		} catch (MessageEncodingException e) {
			throw new ServletException(
					"SAML encoding error: " + e.getMessage(), e);
		}
	}
}
