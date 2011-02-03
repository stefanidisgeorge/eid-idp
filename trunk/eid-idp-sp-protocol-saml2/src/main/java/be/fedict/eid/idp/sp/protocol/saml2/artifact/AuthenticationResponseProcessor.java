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

package be.fedict.eid.idp.sp.protocol.saml2.artifact;

import be.fedict.eid.idp.sp.protocol.saml2.AbstractAuthenticationResponseProcessor;
import be.fedict.eid.idp.sp.protocol.saml2.AuthenticationResponseProcessorException;
import be.fedict.eid.idp.sp.protocol.saml2.spi.AuthenticationResponseService;
import be.fedict.eid.idp.sp.protocol.saml2.spi.artifact.ArtifactAuthenticationResponseService;
import org.opensaml.saml2.core.Response;

import javax.servlet.http.HttpServletRequest;

/**
 * SAML v2.0 Authentication response processor for the Browser HTTP POST binding.
 */
public class AuthenticationResponseProcessor extends AbstractAuthenticationResponseProcessor {

        private final ArtifactAuthenticationResponseService service;

        /**
         * Main Constructor
         *
         * @param service required {@link ArtifactAuthenticationResponseService} for
         *                validation of certificate chain in returned SAML v2.0
         *                Response. Required as the location of the
         *                eID IdP Artifact Service is needed.
         */
        public AuthenticationResponseProcessor(ArtifactAuthenticationResponseService service) {

                this.service = service;
        }

        @Override
        protected Response getSamlResponse(HttpServletRequest request)
                throws AuthenticationResponseProcessorException {

                String encodedArtifact = request.getParameter("SAMLArt");
                if (null == encodedArtifact) {
                        throw new AuthenticationResponseProcessorException(
                                "No SAMLArt parameter found.");
                }
                LOG.debug("Encoded artifact: " + encodedArtifact);

                // TODO: decode artifact
                String artifactId = encodedArtifact;

                String location = this.service.getArtifactServiceLocation();
                LOG.debug("SAML2 Artifact Service: " + location);
                ArtifactServiceClient client = new ArtifactServiceClient(location);
                // TODO: fix me, ability to pass along SSL public key ... for now trust all
                client.setServicePublicKey(null);
                client.setLogging(true);

                return client.resolve(artifactId);
        }

        @Override
        protected AuthenticationResponseService getAuthenticationResponseService() {

                return this.service;
        }
}
