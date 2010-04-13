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

package test.unit.be.fedict.eid.idp.protocol.ws_federation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import javax.servlet.http.HttpServletResponse;

import org.apache.commons.httpclient.Header;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Before;
import org.junit.Test;
import org.mortbay.jetty.testing.ServletTester;

import be.fedict.eid.idp.protocol.ws_federation.WSFederationMetadataHttpServlet;

public class WSFederationMetadataHttpServletTest {

	private static final Log LOG = LogFactory
			.getLog(WSFederationMetadataHttpServletTest.class);

	private ServletTester servletTester;

	private String location;

	@Before
	public void setUp() throws Exception {
		this.servletTester = new ServletTester();
		this.servletTester.setContextPath("/eid-idp");
		this.servletTester.addServlet(WSFederationMetadataHttpServlet.class,
				"/ws-federation-metadata");
		this.servletTester.start();
		this.location = this.servletTester.createSocketConnector(true)
				+ "/eid-idp/ws-federation-metadata";
	}

	@Test
	public void get() throws Exception {
		// setup
		LOG.debug("URL: " + this.location);
		HttpClient httpClient = new HttpClient();
		GetMethod getMethod = new GetMethod(this.location);

		// operate
		int result = httpClient.executeMethod(getMethod);

		// verify
		assertEquals(HttpServletResponse.SC_OK, result);
		String responseBody = getMethod.getResponseBodyAsString();
		LOG.debug("Response body: " + responseBody);
		Header contentTypeHeader = getMethod.getResponseHeader("Content-Type");
		assertNotNull(contentTypeHeader);
		assertEquals("application/samlmetadata+xml", contentTypeHeader
				.getValue());
	}

}
