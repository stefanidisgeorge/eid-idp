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

package test.unit.be.fedict.eid.idp.protocol.openid;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.After;
import org.junit.Test;
import org.mortbay.jetty.testing.ServletTester;
import org.openid4java.OpenIDException;
import org.openid4java.consumer.ConsumerManager;
import org.openid4java.consumer.VerificationResult;
import org.openid4java.discovery.DiscoveryInformation;
import org.openid4java.discovery.Identifier;
import org.openid4java.message.AuthRequest;
import org.openid4java.message.Message;
import org.openid4java.message.ParameterList;
import org.openid4java.server.ServerManager;

public class OpenIDProtocolServiceTest {

	private static final Log LOG = LogFactory
			.getLog(OpenIDProtocolServiceTest.class);

	private ServletTester servletTester;

	private static String location;

	@After
	public void tearDown() throws Exception {
		if (null != this.servletTester) {
			this.servletTester.stop();
		}
	}

	public static class OpenIDIdentityServlet extends HttpServlet {

		private static final long serialVersionUID = 1L;

		private static final Log LOG = LogFactory
				.getLog(OpenIDIdentityServlet.class);

		@Override
		protected void doGet(HttpServletRequest request,
				HttpServletResponse response) throws ServletException,
				IOException {
			LOG.debug("doGet");
			PrintWriter printWriter = response.getWriter();
			printWriter.println("<html>");
			printWriter.println("<head>");
			printWriter.println("<link rel=\"openid.server\" href=\""
					+ OpenIDProtocolServiceTest.location + "/producer\"/>");

			printWriter.println("</head>");
			printWriter.println("<body><p>OpenID Identity URL</p></body>");
			printWriter.println("</html>");
		}

	}

	public static class OpenIDConsumerServlet extends HttpServlet {

		private static final long serialVersionUID = 1L;

		private static final Log LOG = LogFactory
				.getLog(OpenIDConsumerServlet.class);

		@Override
		protected void doGet(HttpServletRequest request,
				HttpServletResponse response) throws ServletException,
				IOException {
			LOG.debug("doGet");
			try {
				ConsumerManager consumerManager = new ConsumerManager();
				String openIdMode = request.getParameter("openid.mode");
				if ("id_res".equals(openIdMode)) {
					LOG.debug("id_res");
					ParameterList parameterList = new ParameterList(request
							.getParameterMap());
					DiscoveryInformation discovered = (DiscoveryInformation) request
							.getSession().getAttribute("openid-disc");
					StringBuffer receivingUrl = request.getRequestURL();
					String queryString = request.getQueryString();
					if (queryString != null && queryString.length() > 0) {
						receivingUrl.append("?").append(queryString);
					}
					VerificationResult verificationResult = consumerManager
							.verify(receivingUrl.toString(), parameterList,
									discovered);
					Identifier identifier = verificationResult.getVerifiedId();
					if (null != identifier) {
						String userId = identifier.getIdentifier();
						LOG.debug("userId");
						PrintWriter printWriter = response.getWriter();
						printWriter.println("<html>");
						printWriter.println("<body>" + userId + "</body>");
						printWriter.println("</html>");
					} else {
						LOG.warn("no verified identifier");
					}
				} else {
					String userIdentifier = OpenIDProtocolServiceTest.location
							+ "/identity";
					List discoveries = consumerManager.discover(userIdentifier);
					DiscoveryInformation discovered = consumerManager
							.associate(discoveries);
					LOG.debug("discovered");
					request.getSession()
							.setAttribute("openid-disc", discovered);
					AuthRequest authRequest = consumerManager.authenticate(
							discovered, OpenIDProtocolServiceTest.location
									+ "/consumer");
					LOG.debug("goto producer");
					response.sendRedirect(authRequest.getDestinationUrl(true));
				}
			} catch (OpenIDException e) {
				throw new ServletException("OpenID error: " + e.getMessage(), e);
			}
		}
	}

	public static class OpenIDProducerServlet extends HttpServlet {

		private static final long serialVersionUID = 1L;

		private static final Log LOG = LogFactory
				.getLog(OpenIDProducerServlet.class);

		@Override
		protected void doGet(HttpServletRequest request,
				HttpServletResponse response) throws ServletException,
				IOException {
			LOG.debug("doGet");
			String openIdMode = request.getParameter("openid.mode");
			if ("checkid_setup".equals(openIdMode)) {
				LOG.debug("checkid_setup");
				ServerManager manager = new ServerManager();
				manager.setOPEndpointUrl(OpenIDProtocolServiceTest.location
						+ "/producer");
				ParameterList parameterList = new ParameterList(request
						.getParameterMap());
				Message message = manager.authResponse(parameterList,
						OpenIDProtocolServiceTest.location + "/identity",
						OpenIDProtocolServiceTest.location + "/identity", true);
				response.sendRedirect(message.getDestinationUrl(true));
			}
		}

		@Override
		protected void doPost(HttpServletRequest request,
				HttpServletResponse response) throws ServletException,
				IOException {
			LOG.debug("doPost");
			String openIdMode = request.getParameter("openid.mode");
			if ("associate".equals(openIdMode)) {
				LOG.debug("associate");
				ServerManager manager = new ServerManager();
				ParameterList parameterList = new ParameterList(request
						.getParameterMap());
				Message message = manager.associationResponse(parameterList);
				String keyValueFormEncoding = message.keyValueFormEncoding();
				LOG.debug("form encoding: " + keyValueFormEncoding);
				PrintWriter printWriter = response.getWriter();
				printWriter.print(keyValueFormEncoding);
			}
		}
	}

	@Test
	public void testOpenIDSpike() throws Exception {
		LOG.debug("OpenID spike");

		// setup
		this.servletTester = new ServletTester();
		this.servletTester.addServlet(OpenIDConsumerServlet.class, "/consumer");
		this.servletTester.addServlet(OpenIDIdentityServlet.class, "/identity");
		this.servletTester.addServlet(OpenIDProducerServlet.class, "/producer");
		this.servletTester.start();
		this.location = this.servletTester.createSocketConnector(true);
		LOG.debug("location: " + this.location);

		HttpClient httpClient = new HttpClient();
		httpClient.getParams().setParameter(
				"http.protocol.allow-circular-redirects", Boolean.TRUE);
		GetMethod getMethod = new GetMethod(this.location + "/consumer");

		// operate
		int statusCode = httpClient.executeMethod(getMethod);

		// verify
		LOG.debug("status code: " + statusCode);
	}
}
