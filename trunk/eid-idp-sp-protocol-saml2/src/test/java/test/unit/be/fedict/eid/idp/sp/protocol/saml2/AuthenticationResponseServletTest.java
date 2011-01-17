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

package test.unit.be.fedict.eid.idp.sp.protocol.saml2;

import be.fedict.eid.idp.sp.protocol.saml2.spi.AuthenticationResponse;
import be.fedict.eid.idp.sp.protocol.saml2.AuthenticationResponseServlet;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.httpclient.Header;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.NameValuePair;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.velocity.Template;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.VelocityEngine;
import org.apache.velocity.runtime.RuntimeConstants;
import org.apache.velocity.runtime.log.JdkLogChute;
import org.joda.time.DateTime;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mortbay.jetty.SessionManager;
import org.mortbay.jetty.servlet.HashSessionManager;
import org.mortbay.jetty.servlet.ServletHolder;
import org.mortbay.jetty.servlet.SessionHandler;
import org.mortbay.jetty.testing.ServletTester;

import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;

import static org.junit.Assert.*;

public class AuthenticationResponseServletTest {

        private static final Log LOG = LogFactory
                .getLog(AuthenticationResponseServletTest.class);

        private ServletTester servletTester;

        private String location;
        private String targetLocation;
        private String errorLocation;

        @Before
        public void setUp() throws Exception {
                this.servletTester = new ServletTester();
                ServletHolder servletHolder = this.servletTester.addServlet(
                        AuthenticationResponseServlet.class, "/response");

                // required init params
                servletHolder.setInitParameter(AuthenticationResponseServlet.
                        RESPONSE_SESSION_ATTRIBUTE_INIT_PARAM, "response");
                servletHolder.setInitParameter(AuthenticationResponseServlet.
                        REDIRECT_PAGE_INIT_PARAM, "/target-page");
                servletHolder.setInitParameter(AuthenticationResponseServlet.
                        ERROR_PAGE_INIT_PARAM, "/error-page");
                servletHolder.setInitParameter(AuthenticationResponseServlet.
                        ERROR_MESSAGE_SESSION_ATTRIBUTE_INIT_PARAM, "ErrorMessage");

                this.servletTester.start();
                String context = this.servletTester.createSocketConnector(true);
                this.location = context + "/response";
                this.targetLocation = context + "/target-page";
                this.errorLocation = context + "/error-page";
        }

        @After
        public void tearDown() throws Exception {
                this.servletTester.stop();
        }

        @Test
        public void testDoGet() throws Exception {
                // setup
                LOG.debug("URL: " + this.location);
                HttpClient httpClient = new HttpClient();
                GetMethod getMethod = new GetMethod(this.location);

                // operate
                int result = httpClient.executeMethod(getMethod);

                // verify
                LOG.debug("result: " + result);

                assertEquals(HttpServletResponse.SC_NOT_FOUND, result);
        }

        @Test
        public void testPostSamlResponse() throws Exception {
                doPostSamlResponseTest("/saml-response.xml");
        }

        //@Test
        public void testPostSignedSamlResponse() throws Exception {
                doPostSamlResponseTest("/saml-response-signed.xml");
        }

        @SuppressWarnings("unchecked")
        private void doPostSamlResponseTest(String samlResponseResourceName)
                throws IOException {
                // setup
                String samlResponse = getSamlResponse(samlResponseResourceName);
                LOG.debug("SAML response: " + samlResponse);
                String encodedSamlResponse = Base64.encodeBase64String(samlResponse
                        .getBytes());

                LOG.debug("URL: " + this.location);
                HttpClient httpClient = new HttpClient();
                PostMethod postMethod = new PostMethod(this.location);
                NameValuePair[] body = {new NameValuePair("SAMLResponse",
                        encodedSamlResponse)};
                postMethod.setRequestBody(body);

                // operate
                int resultStatusCode = httpClient.executeMethod(postMethod);

                // verify
                LOG.debug("result: " + resultStatusCode);
                assertEquals(HttpServletResponse.SC_MOVED_TEMPORARILY, resultStatusCode);
                Header locationHeader = postMethod.getResponseHeader("Location");
                String value = locationHeader.getValue();
                assertEquals(this.targetLocation, value);

                SessionHandler sessionHandler = this.servletTester.getContext()
                        .getSessionHandler();
                SessionManager sessionManager = sessionHandler.getSessionManager();
                LOG.debug("session manager type: "
                        + sessionManager.getClass().getName());
                HashSessionManager hashSessionManager = (HashSessionManager) sessionManager;
                LOG.debug("# sessions: " + hashSessionManager.getSessions());
                assertEquals(1, hashSessionManager.getSessions());
                Map<String, HttpSession> sessionMap = hashSessionManager
                        .getSessionMap();
                LOG.debug("session map: " + sessionMap);
                Entry<String, HttpSession> sessionEntry = sessionMap.entrySet()
                        .iterator().next();
                HttpSession httpSession = sessionEntry.getValue();

                AuthenticationResponse authenticationResponse =
                        (AuthenticationResponse) httpSession.getAttribute("response");
                assertNotNull(authenticationResponse);
                assertEquals("authn-id", authenticationResponse.getIdentifier());

                Map<String, Object> attributeMap = authenticationResponse.getAttributeMap();
                assertNotNull(attributeMap);

                assertTrue(attributeMap.containsKey("urn:be:fedict:eid:idp:name"));
                assertEquals("test-name", attributeMap.get("urn:be:fedict:eid:idp:name"));

                assertTrue(attributeMap.containsKey("urn:be:fedict:eid:idp:firstName"));
                assertEquals("test-first-name", attributeMap.get("urn:be:fedict:eid:idp:firstName"));

                assertTrue(attributeMap.containsKey("urn:be:fedict:eid:idp:gender"));
                assertEquals("MALE", attributeMap.get("urn:be:fedict:eid:idp:gender"));
        }

        private String getSamlResponse(String samlResponseResourceName) throws IOException {

                Properties velocityProperties = new Properties();
                velocityProperties.put("resource.loader", "class");
                velocityProperties.put(RuntimeConstants.RUNTIME_LOG_LOGSYSTEM_CLASS,
                        JdkLogChute.class.getName());
                velocityProperties.put(JdkLogChute.RUNTIME_LOG_JDK_LOGGER,
                        AuthenticationResponseServletTest.class.getName());
                velocityProperties.put("class.resource.loader.class", "" +
                        "org.apache.velocity.runtime.resource.loader.ClasspathResourceLoader");
                velocityProperties.put("file.resource.loader.cache ", "false");
                VelocityEngine velocityEngine;
                try {
                        velocityEngine = new VelocityEngine(velocityProperties);
                        velocityEngine.init();
                } catch (Exception e) {
                        throw new RuntimeException("could not initialize velocity engine", e);
                }

                DateTime now = new DateTime();
                DateTime notOnOrAfter = now.plusMinutes(10);

                VelocityContext velocityContext = new VelocityContext();
                velocityContext.put("NotBefore", now.toString());
                velocityContext.put("NotOnOrAfter", notOnOrAfter.toString());

                Template template;
                try {
                        template = velocityEngine.getTemplate(samlResponseResourceName);
                } catch (Exception e) {
                        throw new RuntimeException("Velocity template error: " + e.getMessage(), e);
                }

                StringWriter stringWriter = new StringWriter();
                PrintWriter writer = new PrintWriter(stringWriter);
                template.merge(velocityContext, writer);
                return stringWriter.toString();
        }
}
