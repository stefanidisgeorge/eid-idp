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

package be.fedict.eid.idp.sp.protocol.simple;

import java.io.IOException;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * eID IdP Simple Protocol Landing Servlet. Can be used by Service Providers
 * (SP) to ease integration of the eID IdP within their web applications.
 * 
 * @author Frank Cornelis
 * 
 */
public class SimpleProtocolLandingServlet extends HttpServlet {

	private static final long serialVersionUID = 1L;

	private static final Log LOG = LogFactory
			.getLog(SimpleProtocolLandingServlet.class);

	private String nameSessionAttribute;

	private String firstNameSessionAttribute;

	private String streetAndNumberSessionAttribute;

	private String zipSessionAttribute;

	private String municipalitySessionAttribute;

	private String redirectPage;

	@Override
	public void init(ServletConfig config) throws ServletException {
		this.nameSessionAttribute = config
				.getInitParameter("NameSessionAttribute");
		this.firstNameSessionAttribute = config
				.getInitParameter("FirstNameSessionAttribute");
		this.streetAndNumberSessionAttribute = config
				.getInitParameter("StreetAndNumberSessionAttribute");
		this.zipSessionAttribute = config
				.getInitParameter("ZipSessionAttribute");
		this.municipalitySessionAttribute = config
				.getInitParameter("MunicipalitySessionAttribute");
		this.redirectPage = config.getInitParameter("RedirectPage");
		if (null == this.redirectPage) {
			throw new ServletException("RedirectPage init-param required");
		}
	}

	@Override
	protected void doPost(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {
		LOG.debug("doPost");
		HttpSession httpSession = request.getSession();
		if (null != this.nameSessionAttribute) {
			String name = request
					.getParameter(SimpleProtocolConstants.NAME_PARAMETER);
			httpSession.setAttribute(this.nameSessionAttribute, name);
		}
		if (null != this.firstNameSessionAttribute) {
			String firstName = request
					.getParameter(SimpleProtocolConstants.FIRST_NAME_PARAMETER);
			httpSession.setAttribute(this.firstNameSessionAttribute, firstName);
		}
		if (null != this.streetAndNumberSessionAttribute) {
			String streetAndNumber = request
					.getParameter(SimpleProtocolConstants.STREET_AND_NUMBER_PARAMETER);
			httpSession.setAttribute(this.streetAndNumberSessionAttribute,
					streetAndNumber);
		}
		if (null != this.zipSessionAttribute) {
			String zip = request
					.getParameter(SimpleProtocolConstants.ZIP_PARAMETER);
			httpSession.setAttribute(this.zipSessionAttribute, zip);
		}
		if (null != this.municipalitySessionAttribute) {
			String municipality = request
					.getParameter(SimpleProtocolConstants.MUNICIPALITY_PARAMETER);
			httpSession.setAttribute(this.municipalitySessionAttribute,
					municipality);
		}
		response.sendRedirect(request.getContextPath() + this.redirectPage);
	}
}
