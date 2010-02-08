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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import be.fedict.eid.idp.model.ProtocolServiceManager;
import be.fedict.eid.idp.spi.IdentityProviderProtocolService;

/**
 * The main entry point for authentication protocols.
 * 
 * @author Frank Cornelis
 * 
 */
public class ProtocolEntryServlet extends HttpServlet {

	private static final long serialVersionUID = 1L;

	private static final Log LOG = LogFactory
			.getLog(ProtocolEntryServlet.class);

	@EJB
	private ProtocolServiceManager protocolServiceManager;

	private String unknownProtocolPageInitParam;

	@Override
	public void init(ServletConfig config) throws ServletException {
		this.unknownProtocolPageInitParam = config
				.getInitParameter("UnknownProtocolPage");
		if (null == this.unknownProtocolPageInitParam) {
			throw new ServletException("UnknownProtocolPage init-param required");
		}
		
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

	private void handleRequest(HttpServletRequest request,
			HttpServletResponse response) throws IOException {
		LOG.debug("handle request");
		String contextPath = request.getContextPath();
		contextPath = contextPath.substring(contextPath.lastIndexOf("/"));
		LOG.debug("context path: " + contextPath);
		IdentityProviderProtocolService protocolService = this.protocolServiceManager
				.findProtocolService(contextPath);
		if (null != protocolService) {
			// TODO
		} else {
			LOG.warn("unsupported protocol: " + contextPath);
			response.sendRedirect(this.unknownProtocolPageInitParam);
		}
	}

}
