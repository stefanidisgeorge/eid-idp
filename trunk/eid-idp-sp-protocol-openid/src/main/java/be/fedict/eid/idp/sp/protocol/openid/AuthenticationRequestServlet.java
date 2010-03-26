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

package be.fedict.eid.idp.sp.protocol.openid;

import java.io.IOException;
import java.util.List;

import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.openid4java.OpenIDException;
import org.openid4java.consumer.ConsumerManager;
import org.openid4java.discovery.DiscoveryInformation;
import org.openid4java.message.AuthRequest;
import org.openid4java.message.ax.FetchRequest;

/**
 * OpenID authentication request servlet.
 * 
 * @author Frank Cornelis
 * 
 */
public class AuthenticationRequestServlet extends HttpServlet {

	private static final long serialVersionUID = 1L;

	private static final Log LOG = LogFactory
			.getLog(AuthenticationRequestServlet.class);

	public static final String CONSUMER_MANAGER_ATTRIBUTE = AuthenticationRequestServlet.class
			.getName()
			+ ".ConsumerManager";

	private boolean parametersFromRequest;

	private String spDestination;

	private String userIdentifier;

	private ConsumerManager consumerManager;

	private boolean trustServer;

	@Override
	public void init(ServletConfig config) throws ServletException {
		String parametersFromRequest = config
				.getInitParameter("ParametersFromRequest");
		if (null != parametersFromRequest) {
			this.parametersFromRequest = Boolean
					.parseBoolean(parametersFromRequest);
		}
		if (false == this.parametersFromRequest) {
			this.spDestination = getRequiredInitParameter("SPDestination",
					config);
			this.userIdentifier = getRequiredInitParameter("UserIdentifier",
					config);
		} else {
			LOG
					.warn("ParametersFromRequest should not be used for production configurations");
		}
		String trustServer = config.getInitParameter("TrustServer");
		if (null != trustServer) {
			this.trustServer = Boolean.parseBoolean(trustServer);
		}
		if (this.trustServer) {
			LOG.warn("Trusting all SSL server certificates!");
			try {
				OpenIDSSLSocketFactory.installAllTrusted();
			} catch (Exception e) {
				throw new ServletException(
						"could not install OpenID SSL Socket Factory: "
								+ e.getMessage(), e);
			}
		}

		ServletContext servletContext = config.getServletContext();
		this.consumerManager = (ConsumerManager) servletContext
				.getAttribute(CONSUMER_MANAGER_ATTRIBUTE);
		if (null == this.consumerManager) {
			try {
				this.consumerManager = new ConsumerManager();
			} catch (Exception e) {
				throw new ServletException(
						"could not init OpenID ConsumerManager");
			}
			servletContext.setAttribute(CONSUMER_MANAGER_ATTRIBUTE,
					this.consumerManager);
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

	@Override
	protected void doGet(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {
		String spDestination;
		String userIdentifier;
		if (this.parametersFromRequest) {
			LOG
					.warn("Retrieving parameters from the request. Only use for debugging!");
			spDestination = request.getParameter("SPDestination");
			if (null == spDestination) {
				throw new ServletException("SPDestination parameter required");
			}
			userIdentifier = request.getParameter("UserIdentifier");
			if (null == userIdentifier) {
				throw new ServletException("UserIdentifier parameter required");
			}
		} else {
			spDestination = this.spDestination;
			userIdentifier = this.userIdentifier;
		}
		try {
			LOG.debug("discovering the identity...");
			List discoveries = this.consumerManager.discover(userIdentifier);
			LOG.debug("associating with the IdP...");
			DiscoveryInformation discovered = this.consumerManager
					.associate(discoveries);
			request.getSession().setAttribute("openid-disc", discovered);

			AuthRequest authRequest = this.consumerManager.authenticate(
					discovered, this.spDestination);
			authRequest.setClaimed(AuthRequest.SELECT_ID);
			authRequest.setIdentity(AuthRequest.SELECT_ID);

			/*
			 * We also piggy-back an attribute fetch request.
			 */
			FetchRequest fetchRequest = FetchRequest.createFetchRequest();
			fetchRequest.addAttribute("fullName",
					"http://axschema.org/namePerson", true);
			authRequest.addExtension(fetchRequest);

			LOG.debug("redirecting to producer with authn request...");
			response.sendRedirect(authRequest.getDestinationUrl(true));
		} catch (OpenIDException e) {
			throw new ServletException("OpenID error: " + e.getMessage(), e);
		}
	}
}
