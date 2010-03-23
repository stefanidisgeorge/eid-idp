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

package be.fedict.eid.idp.protocol.openid;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Servlet that provides the OpenID YADIS identity within the eID Identity
 * Provider service.
 * 
 * @author Frank Cornelis
 * 
 */
public class OpenIDIdentityHttpServlet extends HttpServlet {

	private static final long serialVersionUID = 1L;

	private static final Log LOG = LogFactory
			.getLog(OpenIDIdentityHttpServlet.class);

	@Override
	protected void doGet(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {
		LOG.debug("doGet");
		String location = "https://" + request.getServerName() + ":"
				+ request.getServerPort() + "/eid-idp/";
		LOG.debug("location: " + location);
		PrintWriter printWriter = response.getWriter();
		if (request.getRequestURI().endsWith("/xrds")) {
			LOG.debug("returning the YADIS XRDS document");
			printWriter
					.println("<xrds:XRDS xmlns:xrds=\"xri://$xrds\" xmlns=\"xri://$xrd*($v*2.0)\">");
			printWriter.println("<XRD>");

			printWriter.println("<Service>");
			printWriter
					.println("<Type>http://specs.openid.net/auth/2.0/server</Type>");
			printWriter.println("<URI>" + location + "/protocol/openid</URI>");
			printWriter.println("</Service>");

			printWriter.println("<Service>");
			printWriter
					.println("<Type>http://specs.openid.net/auth/2.0/signon</Type>");
			printWriter.println("<URI>" + location + "/protocol/openid</URI>");
			printWriter.println("</Service>");

			printWriter.println("</XRD>");
			printWriter.println("</xrds:XRDS>");
			return;
		}
		printWriter.println("<html>");
		printWriter.println("<head>");
		printWriter.println("<meta http-equiv=\"X-XRDS-Location\" content=\""
				+ location + "/endpoints/openid-identity/xrds\"/>");
		printWriter.println("</head>");
		printWriter.println("<body><p>OpenID Identity URL</p></body>");
		printWriter.println("</html>");
	}
}
