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

package be.fedict.eid.idp.webapp;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.ejb.EJB;
import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import be.fedict.eid.idp.model.ProtocolServiceManager;
import be.fedict.eid.idp.spi.IdentityProviderFlow;
import be.fedict.eid.idp.spi.IdentityProviderProtocolService;
import be.fedict.eid.idp.spi.protocol.IdentityProviderProtocolType;

/**
 * The main entry point for authentication protocols. This servlet serves as a
 * broker towards the different protocol services. Depending on the context path
 * the request will be delegated towards the correct protocol service.
 * 
 * @author Frank Cornelis
 * 
 */
public class ProtocolEntryServlet extends HttpServlet {

	private static final long serialVersionUID = 1L;

	private static final Log LOG = LogFactory
			.getLog(ProtocolEntryServlet.class);

	public static final String CONTEXT_PATH_SESSION_ATTRIBUTE = ProtocolEntryServlet.class
			.getName()
			+ ".ContextPath";

	public static final String PROTOCOL_SERVICES_ATTRIBUTE = ProtocolEntryServlet.class
			.getName()
			+ ".ProtocolServices";

	@EJB
	private ProtocolServiceManager protocolServiceManager;

	private String unknownProtocolPageInitParam;

	private String protocolErrorPageInitParam;

	private String protocolErrorMessageSessionAttributeInitParam;

	private String identificationPageInitParam;

	private String authenticationWithIdentificationPageInitParam;

	public static Map<String, IdentityProviderProtocolService> getProtocolServices(
			ServletContext servletContext) throws ServletException {
		Map<String, IdentityProviderProtocolService> protocolServices = findProtocolServices(servletContext);
		return protocolServices;
	}

	public static Map<String, IdentityProviderProtocolService> findProtocolServices(
			ServletContext servletContext) throws ServletException {
		Map<String, IdentityProviderProtocolService> protocolServices = (Map<String, IdentityProviderProtocolService>) servletContext
				.getAttribute(PROTOCOL_SERVICES_ATTRIBUTE);
		return protocolServices;
	}

	private static void setProtocolService(
			Map<String, IdentityProviderProtocolService> protocolServices,
			ServletContext servletContext) {
		servletContext.setAttribute(PROTOCOL_SERVICES_ATTRIBUTE,
				protocolServices);
	}

	@Override
	public void init(ServletConfig config) throws ServletException {
		/*
		 * Get init-params.
		 */
		this.unknownProtocolPageInitParam = getRequiredInitParameter(config,
				"UnknownProtocolPage");
		this.protocolErrorPageInitParam = getRequiredInitParameter(config,
				"ProtocolErrorPage");
		this.protocolErrorMessageSessionAttributeInitParam = getRequiredInitParameter(
				config, "ProtocolErrorMessageSessionAttribute");
		this.identificationPageInitParam = getRequiredInitParameter(config,
				"IdentificationPage");
		this.authenticationWithIdentificationPageInitParam = getRequiredInitParameter(
				config, "AuthenticationWithIdentificationPage");

		/*
		 * Initialize the protocol services.
		 */
		ServletContext servletContext = config.getServletContext();
		if (null == findProtocolServices(servletContext)) {
			Map<String, IdentityProviderProtocolService> protocolServices = new HashMap<String, IdentityProviderProtocolService>();
			setProtocolService(protocolServices, servletContext);
			List<IdentityProviderProtocolType> identityProviderProtocols = this.protocolServiceManager
					.getProtocolServices();
			for (IdentityProviderProtocolType identityProviderProtocol : identityProviderProtocols) {
				String name = identityProviderProtocol.getName();
				LOG.debug("protocol name: " + name);
				IdentityProviderProtocolService protocolService = this.protocolServiceManager
						.getProtocolService(identityProviderProtocol);
				String contextPath = identityProviderProtocol.getContextPath();
				if (protocolServices.containsKey(contextPath)) {
					throw new ServletException(
							"protocol service for context path already registered: "
									+ contextPath);
				}
				protocolService.init(servletContext);
				protocolServices.put(contextPath, protocolService);
			}
		}
	}

	private String getRequiredInitParameter(ServletConfig config,
			String initParamName) throws ServletException {
		String value = config.getInitParameter(initParamName);
		if (null == value) {
			throw new ServletException(initParamName + " init-param required");
		}
		return value;
	}

	@Override
	protected void doGet(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {
		handleRequest(request, response);
	}

	@Override
	protected void doPost(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {
		handleRequest(request, response);
	}

	private void setProtocolServiceContextPath(String contextPath,
			HttpServletRequest request) {
		LOG.debug("stored context path: " + contextPath);
		HttpSession httpSession = request.getSession();
		httpSession.setAttribute(CONTEXT_PATH_SESSION_ATTRIBUTE, contextPath);
	}

	public static String getProtocolServiceContextPath(
			HttpServletRequest request) {
		HttpSession httpSession = request.getSession();
		String contextPath = (String) httpSession
				.getAttribute(CONTEXT_PATH_SESSION_ATTRIBUTE);
		return contextPath;
	}

	public static IdentityProviderProtocolService getProtocolService(
			HttpServletRequest request) throws ServletException {
		String contextPath = getProtocolServiceContextPath(request);
		ServletContext servletContext = request.getServletContext();
		Map<String, IdentityProviderProtocolService> protocolServices = getProtocolServices(servletContext);
		IdentityProviderProtocolService protocolService = protocolServices
				.get(contextPath);
		if (null == protocolService) {
			throw new ServletException("no protocol service for context path: "
					+ contextPath);
		}
		return protocolService;
	}

	private void handleRequest(HttpServletRequest request,
			HttpServletResponse response) throws IOException, ServletException {
		LOG.debug("handle request");
		LOG.debug("request URI: " + request.getRequestURI());
		LOG.debug("request method: " + request.getMethod());
		LOG.debug("request path info: " + request.getPathInfo());
		LOG.debug("request context path: " + request.getContextPath());
		LOG.debug("request query string: " + request.getQueryString());
		LOG.debug("request path translated: " + request.getPathTranslated());
		String protocolServiceContextPath = request.getPathInfo();
		setProtocolServiceContextPath(protocolServiceContextPath, request);

		ServletContext servletContext = request.getServletContext();
		Map<String, IdentityProviderProtocolService> protocolServices = getProtocolServices(servletContext);
		IdentityProviderProtocolService protocolService = protocolServices
				.get(protocolServiceContextPath);
		if (null == protocolService) {
			LOG.warn("unsupported protocol: " + protocolServiceContextPath);
			response.sendRedirect(request.getContextPath()
					+ this.unknownProtocolPageInitParam);
			return;
		}

		try {
			IdentityProviderFlow idpFlow = protocolService
					.handleIncomingRequest(request, response);
			if (null == idpFlow) {
				LOG
						.debug("the protocol service handler defined its own response flow");
				return;
			}
			switch (idpFlow) {
			case IDENTIFICATION:
				response.sendRedirect(request.getContextPath()
						+ this.identificationPageInitParam);
				break;
			case AUTHENTICATION_WITH_IDENTIFICATION:
				response.sendRedirect(request.getContextPath()
						+ this.authenticationWithIdentificationPageInitParam);
				break;
			default:
				throw new RuntimeException("cannot handle IdP flow: " + idpFlow);
			}
		} catch (Exception e) {
			LOG.error("protocol error: " + e.getMessage(), e);
			HttpSession httpSession = request.getSession();
			httpSession.setAttribute(
					this.protocolErrorMessageSessionAttributeInitParam, e
							.getMessage());
			response.sendRedirect(request.getContextPath()
					+ this.protocolErrorPageInitParam);
		}
	}
}
