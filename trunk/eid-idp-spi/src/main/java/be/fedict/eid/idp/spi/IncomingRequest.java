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

package be.fedict.eid.idp.spi;

import java.security.cert.X509Certificate;

/**
 * The incoming request. This is used to specify the wanted authentication flow
 * and optionally authenticate the RP.
 *
 * @author Wim Vandenhaute
 */
public class IncomingRequest {

        private final IdentityProviderFlow idpFlow;
        private final String spDomain;
        private final X509Certificate spCertificate;

        /**
         * Main constructor
         *
         * @param idpFlow       authentication flow
         * @param spDomain      optional SP domain, <code>null</code> if empty
         * @param spCertificate optional SP certificate, <code>null</code> if
         *                      empty
         */
        public IncomingRequest(IdentityProviderFlow idpFlow, String spDomain,
                               X509Certificate spCertificate) {
                this.idpFlow = idpFlow;
                this.spDomain = spDomain;
                this.spCertificate = spCertificate;
        }

        public IdentityProviderFlow getIdpFlow() {
                return idpFlow;
        }

        public String getSpDomain() {
                return spDomain;
        }

        public X509Certificate getSpCertificate() {
                return spCertificate;
        }
}