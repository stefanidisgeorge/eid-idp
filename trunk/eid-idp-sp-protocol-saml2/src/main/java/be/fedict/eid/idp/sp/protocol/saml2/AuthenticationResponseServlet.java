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

package be.fedict.eid.idp.sp.protocol.saml2;

import be.fedict.eid.idp.sp.protocol.saml2.spi.AuthenticationResponseService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

/**
 * Processes the response of the SAML v2.0 protocol.
 * <p/>
 * <p>
 * The following init-params are required:
 * </p>
 * <ul>
 * <li><tt>IdentifierSessionAttribute</tt>: indicates the session attribute to
 * store the returned subject identifier.</li>
 * <li><tt>RedirectPage</tt>: indicates the page where to redirect after
 * successfull authentication.</li>
 * <li><tt>ErrorPage</tt>: indicates the page to be shown in case of errors.</li>
 * <li><tt>ErrorMessageSessionAttribute</tt>: indicates which session attribute
 * to use for reporting an error. This session attribute can be used on the
 * error page.</li>
 * </ul>
 * <p/>
 * <p>
 * The following init-params are optional:
 * </p>
 * <ul>
 * <li><tt>AttributeMapSessionAttribute</tt>: indicates the session attribute to
 * store the map of optionally returned attributes.</li>
 * <li><tt>RelayStateSessionAttribute</tt>: indicates the session attribute to
 * store optionally returned relay state.</li>
 * <li><tt>AuthenticationResponseService</tt>: indicates the JNDI location of
 * the {@link AuthenticationResponseService} that can be used optionally for
 * e.g. validation of the certificate chain in the response's signature.
 * </ul>
 */
public class AuthenticationResponseServlet extends HttpServlet {

        private static final long serialVersionUID = 1L;

        private static final Log LOG = LogFactory
                .getLog(AuthenticationResponseServlet.class);

        public static final String IDENTIFIER_SESSION_ATTRIBUTE_INIT_PARAM =
                "IdentifierSessionAttribute";
        public static final String REDIRECT_PAGE_INIT_PARAM =
                "RedirectPage";

        public static final String ATTRIBUTE_MAP_SESSION_ATTRIBUTE_INIT_PARAM =
                "AttributeMapSessionAttribute";
        public static final String RELAY_STATE_SESSION_ATTRIBUTE_INIT_PARAM =
                "RelayStateSessionAttribute";
        public static final String AUTHN_RESPONSE_SERVICE_SESSION_ATTRIBUTE_INIT_PARAM =
                "AuthenticationResponseService";

        public static final String ERROR_PAGE_INIT_PARAM = "ErrorPage";
        public static final String ERROR_MESSAGE_SESSION_ATTRIBUTE_INIT_PARAM =
                "ErrorMessageSessionAttribute";


        private String identifierSessionAttribute;
        private String attributeMapSessionAttribute;

        private String redirectPage;
        private String relayStateSessionAttribute;

        private AuthenticationResponseProcessor authenticationResponseProcessor;

        private String errorPage;
        private String errorMessageSessionAttribute;


        @Override
        public void init(ServletConfig config) throws ServletException {

                this.identifierSessionAttribute = getRequiredInitParameter(
                        IDENTIFIER_SESSION_ATTRIBUTE_INIT_PARAM, config);
                this.redirectPage = getRequiredInitParameter(
                        REDIRECT_PAGE_INIT_PARAM, config);

                this.attributeMapSessionAttribute = config
                        .getInitParameter(ATTRIBUTE_MAP_SESSION_ATTRIBUTE_INIT_PARAM);
                this.relayStateSessionAttribute = config
                        .getInitParameter(RELAY_STATE_SESSION_ATTRIBUTE_INIT_PARAM);

                this.errorPage = getRequiredInitParameter(ERROR_PAGE_INIT_PARAM,
                        config);
                this.errorMessageSessionAttribute = getRequiredInitParameter(
                        ERROR_MESSAGE_SESSION_ATTRIBUTE_INIT_PARAM, config);

                this.authenticationResponseProcessor =
                        new AuthenticationResponseProcessor(config
                                .getInitParameter(AUTHN_RESPONSE_SERVICE_SESSION_ATTRIBUTE_INIT_PARAM));
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
                             HttpServletResponse response)
                throws ServletException, IOException {

                showErrorPage("SAML2 response handler not available via GET", null,
                        request, response);
        }

        @Override
        @SuppressWarnings("unchecked")
        protected void doPost(HttpServletRequest request,
                              HttpServletResponse response) throws ServletException, IOException {
                LOG.debug("doPost");

                // clear old session attributes
                HttpSession httpSession = request.getSession();
                clearAllSessionAttribute(httpSession);

                // process response
                AuthenticationResponse authenticationResponse;
                try {
                        authenticationResponse =
                                this.authenticationResponseProcessor.process(request);
                } catch (AuthenticationResponseProcessorException e) {
                        showErrorPage(e.getMessage(), e, request, response);
                        return;
                }

                // save response info to session
                httpSession.setAttribute(this.identifierSessionAttribute,
                        authenticationResponse.getIdentifier());

                if (null != this.attributeMapSessionAttribute) {
                        httpSession.setAttribute(this.attributeMapSessionAttribute,
                                authenticationResponse.getAttributeMap());
                }

                if (null != this.relayStateSessionAttribute) {
                        LOG.debug("relay state: " + authenticationResponse.getRelayState());
                        httpSession.setAttribute(this.relayStateSessionAttribute,
                                authenticationResponse.getRelayState());
                }

                // done, redirect
                response.sendRedirect(request.getContextPath() + this.redirectPage);
        }

        private void showErrorPage(String errorMessage, Throwable cause,
                                   HttpServletRequest request, HttpServletResponse response)
                throws IOException, ServletException {

                if (null == cause) {
                        LOG.error("Error: " + errorMessage);
                } else {
                        LOG.error("Error: " + errorMessage, cause);
                }
                request.getSession().setAttribute(
                        this.errorMessageSessionAttribute, errorMessage);
                response.sendRedirect(request.getContextPath() + this.errorPage);
        }

        private void clearAllSessionAttribute(HttpSession httpSession) {

                httpSession.removeAttribute(this.identifierSessionAttribute);
                httpSession.removeAttribute(this.attributeMapSessionAttribute);
                httpSession.removeAttribute(this.relayStateSessionAttribute);
        }
}
