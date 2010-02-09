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

import javax.ejb.EJB;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import be.fedict.eid.idp.model.ProtocolServiceManager;
import be.fedict.eid.idp.spi.IdentityProviderProtocolService;
import be.fedict.eid.idp.spi.IdentityProviderProtocolService.IdentityProviderFlow;

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

	@EJB
	private ProtocolServiceManager protocolServiceManager;

	private String unknownProtocolPageInitParam;

	private String protocolErrorPageInitParam;

	private String protocolErrorMessageSessionAttributeInitParam;

	private String identificationPageInitParam;

	@Override
	public void init(ServletConfig config) throws ServletException {
		this.unknownProtocolPageInitParam = getRequiredInitParameter(config,
				"UnknownProtocolPage");
		this.protocolErrorPageInitParam = getRequiredInitParameter(config,
				"ProtocolErrorPage");
		this.protocolErrorMessageSessionAttributeInitParam = getRequiredInitParameter(
				config, "ProtocolErrorMessageSessionAttribute");
		this.identificationPageInitParam = getRequiredInitParameter(config,
				"IdentificationPage");
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

	private void handleRequest(HttpServletRequest request,
			HttpServletResponse response) throws IOException {
		LOG.debug("handle request");
		LOG.debug("request URI: " + request.getRequestURI());
		LOG.debug("request method: " + request.getMethod());
		LOG.debug("request path info: " + request.getPathInfo());
		LOG.debug("request context path: " + request.getContextPath());
		LOG.debug("request query string: " + request.getQueryString());
		LOG.debug("request path translated: " + request.getPathTranslated());
		String protocolServiceContextPath = request.getPathInfo();
		setProtocolServiceContextPath(protocolServiceContextPath, request);
		/*
		 * TODO: optimize, no need to scan the classpath in search for protocol
		 * services each time.
		 */
		IdentityProviderProtocolService protocolService = this.protocolServiceManager
				.findProtocolService(protocolServiceContextPath);
		if (null != protocolService) {
			try {
				IdentityProviderFlow idpFlow = protocolService
						.handleIncomingRequest(request);
				switch (idpFlow) {
				case IDENTIFICATION:
					response.sendRedirect(request.getContextPath()
							+ this.identificationPageInitParam);
					break;
				default:
					throw new RuntimeException("cannot handle IdP flow: "
							+ idpFlow);
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
		} else {
			LOG.warn("unsupported protocol: " + protocolServiceContextPath);
			response.sendRedirect(request.getContextPath()
					+ this.unknownProtocolPageInitParam);
		}
	}
}
