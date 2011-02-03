/*
 * eID Identity Provider Project.
 * Copyright (C) 2011 FedICT.
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

package be.fedict.eid.idp.sp.protocol.saml2.spi;

import java.security.KeyStore;
import java.util.Map;

/**
 * SPI for authentication request services. Using an authentication request
 * service allows for run-time configuration of the
 * AuthenticationRequestServlet.
 *
 * @author Frank Cornelis.
 */
public interface AuthenticationRequestService {

        /**
         * Gives back the Service Provider destination endpoint that will handle
         * the returned SAML v2.0 Response.
         *
         * @return SP SAML2 response handling location.
         */
        String getSPDestination();

        /**
         * Gives back the destination URL of the eID IdP SAML2 protocol entry point.
         *
         * @return eID IdP SAML2 entry point
         */
        String getIdPDestination();

        /**
         * Gives back the relay state to be used towards the eID IdP SAML2 protocol
         * entry point.
         *
         * @param parameterMap the HTTP parameter map.
         * @return relay state
         */
        String getRelayState(Map<String, String[]> parameterMap);

        /**
         * Gives back the optional Service Provider's identity to be used to
         * sign outgoing SAML2 authentication requests.
         *
         * @return private key entry of the SP or <code>null</code> if no
         *         signing is needed.
         */
        KeyStore.PrivateKeyEntry getSPIdentity();
}
