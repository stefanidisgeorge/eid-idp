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

package be.fedict.eid.idp.sp.protocol.ws_federation;

import be.fedict.eid.idp.common.saml2.AssertionValidationException;
import be.fedict.eid.idp.common.saml2.AuthenticationResponse;
import be.fedict.eid.idp.common.saml2.Saml2Util;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.ws.wstrust.*;
import org.opensaml.xml.XMLObject;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;

/**
 * WS-Federation Authentication Response Servlet.
 * <p/>
 * This servlet will process the incoming WS-Federation Authentication Response
 * and construct a {@link AuthenticationResponse} from it, putting on the
 * requested HTTP Session parameter. After this it will redirect to the
 * configured redirect page
 * <p/>
 * Required intialization parameters are:
 * <ul>
 * <li><tt>ResponseSessionAttribute</tt>: HTTP Session Attribute on which the
 * {@link AuthenticationResponse} will be set.</li>
 * <li><tt>RedirectPage</tt>: Page to redirect to after having processed the
 * OpenID ID Resolution response</li>
 * </ul>
 */
public class AuthenticationResponseServlet extends HttpServlet {

        private static final long serialVersionUID = 1L;

        private static final Log LOG = LogFactory
                .getLog(AuthenticationResponseServlet.class);

        private String responseSessionAttribute;

        private String redirectPage;

        /**
         * {@inheritDoc}
         */
        @Override
        public void init(ServletConfig config) throws ServletException {
                this.responseSessionAttribute = getRequiredInitParameter(
                        "ResponseSessionAttribute", config);
                this.redirectPage = getRequiredInitParameter("RedirectPage", config);
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

        /**
         * {@inheritDoc}
         */
        @Override
        protected void doGet(HttpServletRequest request,
                             HttpServletResponse response)
                throws ServletException, IOException {

                throw new ServletException("GET not available");
        }

        /**
         * {@inheritDoc}
         */
        @Override
        protected void doPost(HttpServletRequest request,
                              HttpServletResponse response)
                throws ServletException, IOException {

                LOG.debug("doPost");

                // get request state
                String context = AuthenticationRequestServlet.getContext(
                        request.getSession());
                String recipient = AuthenticationRequestServlet.getRecipient(
                        request.getSession());

                // check wa
                String wa = request.getParameter("wa");
                if (null == wa) {
                        throw new ServletException("Missing \"wa\" param.");
                }
                if (!wa.equals("wsignin1.0")) {
                        throw new ServletException("Unexpected value for \"wa\" param.");
                }

                // validate optional ctx
                validateContext(context, request.getParameter("wctx"));

                // get wresult
                String wresult = request.getParameter("wresult");
                LOG.debug("wresult=" + wresult);

                RequestSecurityTokenResponseCollection rstCollections = Saml2Util.unmarshall(
                        Saml2Util.parseDocument(wresult).getDocumentElement());

                if (rstCollections.getRequestSecurityTokenResponses().size() != 1) {
                        throw new ServletException("Expected exactly 1 RequestSecurityTokenResponse");
                }

                RequestSecurityTokenResponse rstResponse =
                        rstCollections.getRequestSecurityTokenResponses().get(0);

                // context
                validateContext(context, rstResponse.getContext());

                // tokentype
                validateTokenType(rstResponse);

                // requesttype
                validateRequestType(rstResponse);

                // keytype
                validateKeyType(rstResponse);

                // validate security token
                Assertion assertion = validateSecurityToken(rstResponse);

                // validate assertion
                DateTime now = new DateTime();
                AuthenticationResponse authenticationResponse;
                try {
                        // TODO: support configurable time offset + encryption keys...
                        authenticationResponse = Saml2Util.validateAssertion(
                                assertion, now, 5, recipient,
                                null, null, null);
                } catch (AssertionValidationException e) {
                        throw new ServletException(e);
                }

                // save response info to session
                request.getSession().setAttribute(this.responseSessionAttribute,
                        authenticationResponse);

                // done, redirect
                response.sendRedirect(request.getContextPath() + this.redirectPage);
        }

        private Assertion validateSecurityToken(RequestSecurityTokenResponse rstResponse)
                throws ServletException {

                List<XMLObject> securityTokens =
                        rstResponse.getUnknownXMLObjects(RequestedSecurityToken.ELEMENT_NAME);
                if (securityTokens.size() != 1) {
                        throw new ServletException("Expected exactly 1 " +
                                "RequestedSecurityToken element.");
                }

                RequestedSecurityToken securityToken =
                        (RequestedSecurityToken) securityTokens.get(0);

                if (!(securityToken.getUnknownXMLObject() instanceof Assertion)) {
                        throw new ServletException("Expected a SAML v2.0 " +
                                "Assertion as SecurityToken!");
                }

                return (Assertion) securityToken.getUnknownXMLObject();
        }

        private void validateKeyType(RequestSecurityTokenResponse rstResponse)
                throws ServletException {

                List<XMLObject> keyTypes =
                        rstResponse.getUnknownXMLObjects(KeyType.ELEMENT_NAME);
                if (keyTypes.size() != 1) {
                        throw new ServletException("Expected exactly 1 KeyType element.");
                }
                if (!((KeyType) keyTypes.get(0)).getValue().equals(
                        "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer")) {
                        throw new ServletException("Unexpected KeyType value.");
                }
        }

        private void validateRequestType(RequestSecurityTokenResponse rstResponse)
                throws ServletException {

                List<XMLObject> requestTypes =
                        rstResponse.getUnknownXMLObjects(RequestType.ELEMENT_NAME);
                if (requestTypes.size() != 1) {
                        throw new ServletException("Expected exactly 1 RequestType element.");
                }
                if (!((RequestType) requestTypes.get(0)).getValue().equals(
                        "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue")) {
                        throw new ServletException("Unexpected RequestType value.");
                }
        }

        private void validateTokenType(RequestSecurityTokenResponse rstResponse)
                throws ServletException {

                List<XMLObject> tokenTypes =
                        rstResponse.getUnknownXMLObjects(TokenType.ELEMENT_NAME);
                if (tokenTypes.size() != 1) {
                        throw new ServletException("Expected exactly 1 TokenType element.");
                }
                if (!((TokenType) tokenTypes.get(0)).getValue().equals(SAMLConstants.SAML20_NS)) {
                        throw new ServletException("Unexpected TokenType value.");
                }
        }

        private void validateContext(String expectedContext, String context)
                throws ServletException {

                if (null != expectedContext) {
                        if (null == context) {
                                throw new ServletException("Missing wctx in response.");
                        } else if (!expectedContext.equals(context)) {
                                throw new ServletException("Wrong wctx in response.");
                        }
                }

        }
}
