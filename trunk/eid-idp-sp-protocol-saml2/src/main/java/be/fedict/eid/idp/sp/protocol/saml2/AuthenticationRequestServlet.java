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
 * <p>
 * The following init-params are required:
 * </p>
 * <ul>
 * <li><tt>SPDestination</tt> or <tt>SPDestinationPage</tt>: Service Provider
 * destination that will handle the returned SAML2 response. One of the 2
 * parameters needs to be specified.</li>
 * </ul>
 * <p/>
 * <p>
 * The following init-params are optional:
 * </p>
 * <ul>
 * <li><tt>IdPDestination</tt>: optional SAML2 entry point of the eID IdP.</li>
 * <li><tt>AuthenticationRequestService</tt>: optional {@link AuthenticationRequestService}
 * to provide the IdP protocol entry point, SP identity for signing the
 * authentication request, relay state..</li>
 * </ul>
 */
public class AuthenticationRequestServlet extends HttpServlet {

        private static final long serialVersionUID = 1L;

        private static final Log LOG = LogFactory
                .getLog(AuthenticationRequestServlet.class);

        private String idpDestination;

        private String spDestination;

        private String spDestinationPage;

        private ServiceLocator<AuthenticationRequestService> authenticationRequestServiceLocator;

        @Override
        public void init(ServletConfig config) throws ServletException {
                this.idpDestination = config.getInitParameter("IdPDestination");
                this.authenticationRequestServiceLocator = new
                        ServiceLocator<AuthenticationRequestService>
                        ("AuthenticationRequestService", config);
                if (null == this.idpDestination
                        && null == this.authenticationRequestServiceLocator.locateService()) {
                        throw new ServletException(
                                "need to provide either IdPDestination or " +
                                        "AuthenticationRequestService(Class) init-params");
                }

                this.spDestination = config.getInitParameter("SPDestination");
                this.spDestinationPage = config
                        .getInitParameter("SPDestinationPage");
                if (null == this.spDestination && null == this.spDestinationPage) {
                        throw new ServletException(
                                "need to provide either SPDestination or " +
                                        "SPDestinationPage init-param");
                }
        }

        @SuppressWarnings("unchecked")
        @Override
        protected void doGet(HttpServletRequest request,
                             HttpServletResponse response) throws ServletException, IOException {
                LOG.debug("doGet");

                String idpDestination;
                String spDestination;
                String relayState;
                KeyStore.PrivateKeyEntry spIdentity = null;

                AuthenticationRequestService service =
                        this.authenticationRequestServiceLocator.locateService();
                if (null != service) {
                        idpDestination = service.getIdPDestination();
                        relayState = service.getRelayState(request.getParameterMap());
                        spIdentity = service.getSPIdentity();
                } else {
                        idpDestination = this.idpDestination;
                        relayState = null;
                }

                if (null != this.spDestination) {
                        spDestination = this.spDestination;
                } else {
                        spDestination = request.getScheme() + "://"
                                + request.getServerName() + ":"
                                + request.getServerPort() + request.getContextPath()
                                + this.spDestinationPage;
                }

                // generate and send an authentication request
                AuthenticationRequestUtil.sendRequest(idpDestination, spDestination,
                        relayState, spIdentity, response);
        }
}
