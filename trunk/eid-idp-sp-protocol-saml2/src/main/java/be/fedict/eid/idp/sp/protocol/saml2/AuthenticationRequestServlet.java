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

import be.fedict.eid.idp.sp.protocol.saml2.spi.AuthenticationRequestService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.KeyStore;

/**
 * Generates and sends out a SAML v2.0 Authentication Request.
 * <p/>
 * <p/>
 * Configuration can be provided either by providing:
 * <ul>
 * <li><tt>AuthenticationRequestService</tt>: {@link AuthenticationRequestService}
 * to provide the IdP protocol entry point, SP response handling location,
 * SP identity for signing the * authentication request, relay state,...</li>
 * </ul>
 * or by provinding:
 * <ul>
 * <li><tt>SPDestination</tt> or <tt>SPDestinationPage</tt>: Service Provider
 * destination that will handle the returned SAML2 response. One of the 2
 * parameters needs to be specified.</li>
 * <li><tt>IdPDestination</tt>: SAML2 entry point of the eID IdP.</li>
 * </ul>
 */
public class AuthenticationRequestServlet extends HttpServlet {

        private static final long serialVersionUID = 1L;

        private static final Log LOG = LogFactory
                .getLog(AuthenticationRequestServlet.class);

        private static final String AUTHN_REQUEST_SERVICE_PARAM =
                "AuthenticationRequestService";
        private static final String IDP_DESTINATION_PARAM =
                "IdPDestination";
        private static final String SP_DESTINATION_PARAM =
                "SPDestination";
        private static final String SP_DESTINATION_PAGE_PARAM =
                SP_DESTINATION_PARAM + "Page";

        private String idpDestination;
        private String spDestination;
        private String spDestinationPage;

        private ServiceLocator<AuthenticationRequestService> authenticationRequestServiceLocator;

        @Override
        public void init(ServletConfig config) throws ServletException {

                this.idpDestination = config.getInitParameter(IDP_DESTINATION_PARAM);
                this.spDestination = config.getInitParameter(SP_DESTINATION_PARAM);
                this.spDestinationPage = config.getInitParameter(SP_DESTINATION_PAGE_PARAM);
                this.authenticationRequestServiceLocator = new
                        ServiceLocator<AuthenticationRequestService>
                        (AUTHN_REQUEST_SERVICE_PARAM, config);

                // validate necessary configuration params
                if (null == this.idpDestination
                        && !this.authenticationRequestServiceLocator.isConfigured()) {
                        throw new ServletException(
                                "need to provide either " + IDP_DESTINATION_PARAM
                                        + " or " + AUTHN_REQUEST_SERVICE_PARAM +
                                        "(Class) init-params");
                }

                if (null == this.spDestination && null == this.spDestinationPage
                        && !this.authenticationRequestServiceLocator.isConfigured()) {
                        throw new ServletException(
                                "need to provide either " + SP_DESTINATION_PARAM
                                        + " or " + SP_DESTINATION_PAGE_PARAM +
                                        " or " + AUTHN_REQUEST_SERVICE_PARAM +
                                        "(Class) init-param");
                }
        }

        @SuppressWarnings("unchecked")
        @Override
        protected void doGet(HttpServletRequest request,
                             HttpServletResponse response) throws ServletException, IOException {
                LOG.debug("doGet");

                String issuer;
                String idpDestination;
                String spDestination;
                String relayState;
                KeyStore.PrivateKeyEntry spIdentity = null;

                AuthenticationRequestService service =
                        this.authenticationRequestServiceLocator.locateService();
                if (null != service) {
                        issuer = service.getIssuer();
                        idpDestination = service.getIdPDestination();
                        relayState = service.getRelayState(request.getParameterMap());
                        spIdentity = service.getSPIdentity();
                        spDestination = service.getSPDestination();
                } else {
                        idpDestination = this.idpDestination;
                        relayState = null;
                        if (null != this.spDestination) {
                                spDestination = this.spDestination;
                        } else {
                                spDestination = request.getScheme() + "://"
                                        + request.getServerName() + ":"
                                        + request.getServerPort() + request.getContextPath()
                                        + this.spDestinationPage;
                        }
                        issuer = spDestination;
                }


                // generate and send an authentication request
                AuthenticationRequestUtil.sendRequest(issuer, idpDestination,
                        spDestination, relayState, spIdentity, response);
        }
}
