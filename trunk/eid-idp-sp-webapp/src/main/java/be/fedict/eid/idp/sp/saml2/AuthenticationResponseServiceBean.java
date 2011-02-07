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

package be.fedict.eid.idp.sp.saml2;

import be.fedict.eid.idp.common.SamlAuthenticationPolicy;
import be.fedict.eid.idp.sp.PkiServlet;
import be.fedict.eid.idp.sp.protocol.saml2.spi.artifact.ArtifactAuthenticationResponseService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.Serializable;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.List;

public class AuthenticationResponseServiceBean implements ArtifactAuthenticationResponseService, Serializable {

        private static final Log LOG = LogFactory.getLog(AuthenticationResponseServiceBean.class);
        private static final long serialVersionUID = 8779248652700835953L;

        private String artifactServiceLocation;

        @Override
        public void validateServiceCertificate(SamlAuthenticationPolicy authenticationPolicy,
                                               List<X509Certificate> certificateChain)
                throws SecurityException {

                LOG.debug("validate saml response policy=" + authenticationPolicy.getUri()
                        + " cert.chain.size=" + certificateChain.size());
        }

        @Override
        public int getMaximumTimeOffset() {
                return 5;
        }

        @Override
        public String getArtifactServiceLocation() {

                return this.artifactServiceLocation;
        }

        @Override
        public boolean logSoapMessages() {
                return true;
        }

        @Override
        public PublicKey getServicePublicKey() {
                return null;
        }

        @Override
        public String getServiceHostname() {
                return null;
        }

        @Override
        public String getProxyHost() {
                return null;
        }

        @Override
        public int getProxyPort() {
                return 0;
        }

        @Override
        public KeyStore.PrivateKeyEntry getSPIdentity() {

                try {
                        return PkiServlet.getPrivateKeyEntry();
                } catch (Exception e) {
                        LOG.error(e);
                        return null;
                }
        }

        public void setArtifactServiceLocation(String artifactServiceLocation) {

                this.artifactServiceLocation = artifactServiceLocation;
        }
}
