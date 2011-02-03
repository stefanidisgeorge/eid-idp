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

package be.fedict.eid.idp.protocol.saml2.artifact;

import be.fedict.eid.idp.common.saml2.Saml2Util;
import be.fedict.eid.idp.protocol.saml2.AbstractSAML2MetadataHttpServlet;
import be.fedict.eid.idp.spi.IdPIdentity;
import be.fedict.eid.idp.spi.IdentityProviderProtocolService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.ArtifactResolutionService;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;

import javax.servlet.http.HttpServletRequest;

public abstract class AbstractSAML2ArtifactMetadataHttpServlet extends AbstractSAML2MetadataHttpServlet {

        private static final Log LOG = LogFactory
                .getLog(AbstractSAML2ArtifactMetadataHttpServlet.class);

        private static final long serialVersionUID = 3275535116892764771L;

        public EntityDescriptor getEntityDescriptor(HttpServletRequest request,
                                                    IdPIdentity identity) {

                String artifactResolutionLocation = "https://"
                        + request.getServerName() + ":"
                        + request.getServerPort() + request.getContextPath()
                        + IdentityProviderProtocolService.WS_ENDPOINT_CONTEXT_PATH
                        + "/saml2/artifact";
                LOG.debug("Artifact resolution location: " + artifactResolutionLocation);

                EntityDescriptor entityDescriptor = super.getEntityDescriptor(
                        request, identity);

                // add ArtifactResolutionService
                ArtifactResolutionService artifactResolutionService =
                        Saml2Util.buildXMLObject(
                                ArtifactResolutionService.class,
                                ArtifactResolutionService.DEFAULT_ELEMENT_NAME);
                artifactResolutionService.setLocation(artifactResolutionLocation);
                artifactResolutionService.setBinding(
                        SAMLConstants.SAML2_SOAP11_BINDING_URI);
                artifactResolutionService.setIndex(0);
                artifactResolutionService.setIsDefault(true);

                SPSSODescriptor spssoDescriptor =
                        (SPSSODescriptor) entityDescriptor.getRoleDescriptors().get(0);
                spssoDescriptor.getArtifactResolutionServices().add(artifactResolutionService);

                return entityDescriptor;
        }
}
