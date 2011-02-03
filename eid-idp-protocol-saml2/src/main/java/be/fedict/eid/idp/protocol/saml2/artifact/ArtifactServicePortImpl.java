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
import be.fedict.eid.idp.protocol.saml2.AbstractSAML2ProtocolService;
import be.fedict.eid.idp.saml2.ws.ArtifactServicePortType;
import be.fedict.eid.idp.spi.IdPIdentity;
import be.fedict.eid.idp.spi.IdentityProviderConfiguration;
import oasis.names.tc.saml._2_0.protocol.ArtifactResolveType;
import oasis.names.tc.saml._2_0.protocol.ArtifactResponseType;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.binding.artifact.SAMLArtifactMap;
import org.opensaml.saml2.core.ArtifactResponse;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.xml.io.MarshallingException;
import org.w3c.dom.Element;

import javax.annotation.Resource;
import javax.jws.WebService;
import javax.servlet.ServletContext;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.ws.WebServiceContext;
import javax.xml.ws.handler.MessageContext;
import java.util.UUID;

@WebService(endpointInterface = "be.fedict.eid.idp.saml2.ws.ArtifactServicePortType")
public class ArtifactServicePortImpl implements ArtifactServicePortType {

        private static final Log LOG = LogFactory
                .getLog(ArtifactServicePortImpl.class);

        @Resource
        private WebServiceContext context;

        public ArtifactResponseType resolve(ArtifactResolveType artifactResolve) {

                LOG.debug("Resolve: " + artifactResolve.getArtifact());

                // get SAML Artifact Map
                ServletContext servletContext =
                        (ServletContext) context.getMessageContext()
                                .get(MessageContext.SERVLET_CONTEXT);
                SAMLArtifactMap artifactMap =
                        AbstractSAML2ArtifactProtocolService.getArtifactMap(
                                servletContext);

                SAMLArtifactMap.SAMLArtifactMapEntry entry =
                        artifactMap.get(artifactResolve.getArtifact());

                // Construct response
                ArtifactResponse artifactResponse = getArtifactResponse(
                        artifactResolve.getID());

                // Add entry if found and remove from map
                if (null != entry) {
                        LOG.debug("response found and added");
                        artifactResponse.setMessage(entry.getSamlMessage());
                        artifactMap.remove(artifactResolve.getArtifact());
                }

                // Sign response if an IdP Identity exists
                IdentityProviderConfiguration configuration =
                        AbstractSAML2ProtocolService.getIdPConfiguration(servletContext);
                IdPIdentity idpIdentity = configuration.findIdentity();
                if (null != idpIdentity) {
                        Saml2Util.sign(artifactResponse, idpIdentity.getPrivateKeyEntry());
                }

                return toJAXB(artifactResponse);
        }

        private ArtifactResponse getArtifactResponse(String inResponseTo) {

                ArtifactResponse artifactResponse = Saml2Util.buildXMLObject(
                        ArtifactResponse.class, ArtifactResponse.DEFAULT_ELEMENT_NAME);
                DateTime issueInstant = new DateTime();
                artifactResponse.setIssueInstant(issueInstant);
                artifactResponse.setVersion(SAMLVersion.VERSION_20);
                artifactResponse.setID(UUID.randomUUID().toString());
                artifactResponse.setInResponseTo(inResponseTo);

                Status status = Saml2Util.buildXMLObject(Status.class,
                        Status.DEFAULT_ELEMENT_NAME);
                artifactResponse.setStatus(status);
                StatusCode statusCode = Saml2Util.buildXMLObject(StatusCode.class,
                        StatusCode.DEFAULT_ELEMENT_NAME);
                status.setStatusCode(statusCode);
                statusCode.setValue(StatusCode.SUCCESS_URI);

                return artifactResponse;
        }

        @SuppressWarnings("unchecked")
        private ArtifactResponseType toJAXB(ArtifactResponse artifactResponse) {

                try {
                        Element element = Configuration.getMarshallerFactory()
                                .getMarshaller(artifactResponse)
                                .marshall(artifactResponse);
                        return ((JAXBElement<ArtifactResponseType>) JAXBContext
                                .newInstance(ArtifactResponseType.class)
                                .createUnmarshaller()
                                .unmarshal(element)).getValue();


                } catch (MarshallingException e) {
                        throw new RuntimeException(e);
                } catch (JAXBException e) {
                        throw new RuntimeException(e);
                }

        }
}
