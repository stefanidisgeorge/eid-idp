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

import be.fedict.eid.idp.saml2.ws.ArtifactService;
import be.fedict.eid.idp.saml2.ws.ArtifactServiceFactory;
import be.fedict.eid.idp.saml2.ws.ArtifactServicePortType;
import be.fedict.eid.idp.saml2.ws.LoggingSoapHandler;
import oasis.names.tc.saml._2_0.protocol.ArtifactResolveType;
import oasis.names.tc.saml._2_0.protocol.ArtifactResponseType;
import oasis.names.tc.saml._2_0.protocol.ObjectFactory;
import oasis.names.tc.saml._2_0.protocol.ResponseType;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.Configuration;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.ws.Binding;
import javax.xml.ws.BindingProvider;
import javax.xml.ws.handler.Handler;
import java.util.Iterator;
import java.util.List;
import java.util.UUID;

/**
 * Client for the SAML v2.0 Artifact Binding Service.
 *
 * @author Wim Vandenhaute
 */
public class ArtifactServiceClient {

        private static final Log LOG = LogFactory
                .getLog(ArtifactServiceClient.class);

        private final ArtifactServicePortType port;

        public ArtifactServiceClient(String location) {

                ArtifactService artifactService =
                        ArtifactServiceFactory.getInstance();
                this.port = artifactService.getArtifactServicePort();

                setEndpointAddress(location);
        }

        /**
         * Enables/disables logging of all SOAP requests/responses.
         */
        public void setLogging(boolean logging) {

                if (logging) {
                        registerLoggerHandler();
                } else {
                        removeLoggerHandler();
                }
        }

        /**
         * Resolve the specified artifact ID via the eID IdP's SAML v2.0
         * Artifact Service
         *
         * @param artifactId ID of to be resolved SAML v2.0 artifact.
         * @return SAML v2.0 Response
         */
        public Response resolve(String artifactId) {

                LOG.debug("resolve: " + artifactId);

                ObjectFactory objectFactory = new ObjectFactory();
                ArtifactResolveType artifactResolve =
                        objectFactory.createArtifactResolveType();

                String resolveId = UUID.randomUUID().toString();

                artifactResolve.setArtifact(artifactId);
                artifactResolve.setID(resolveId);

                ArtifactResponseType response = this.port.resolve(artifactResolve);

                if (null == response) {
                        throw new RuntimeException("No Artifact Response returned");
                }

                if (null == response.getStatus()) {
                        throw new RuntimeException("No Status Code in Artifact Response");
                }

                if (!response.getStatus().getStatusCode().getValue().equals(
                        StatusCode.SUCCESS_URI)) {
                        // TODO: handle nicely, same for other RuntimeExceptions...
                        throw new RuntimeException("Resolve failed: " +
                                response.getStatus().getStatusCode().getValue());
                }

                if (!response.getInResponseTo().equals(resolveId)) {
                        throw new RuntimeException("Response not matching resolve?");
                }

                if (null == response.getAny()) {
                        throw new RuntimeException("No content in Artifact Response?");
                }

                if (!(response.getAny() instanceof ResponseType)) {
                        throw new RuntimeException("Unexpected content in Artifact Response.");
                }

                ResponseType samlResponseType = (ResponseType) response.getAny();

                return toSAML(samlResponseType);
        }

        public static Response toSAML(final ResponseType responseType) {

                try {
                        Document root = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
                        JAXBContext.newInstance(ResponseType.class).
                                createMarshaller().
                                marshal(new JAXBElement<ResponseType>(
                                        Response.DEFAULT_ELEMENT_NAME,
                                        ResponseType.class, responseType), root);

                        return unmarshall(root.getDocumentElement());
                } catch (ParserConfigurationException e) {
                        throw new RuntimeException("Default parser configuration " +
                                "failed.", e);
                } catch (JAXBException e) {
                        throw new RuntimeException("Marshaling to OpenSAML " +
                                "object failed.", e);
                }
        }

        @SuppressWarnings({"unchecked"})
        public static <X extends XMLObject> X unmarshall(Element xmlElement) {

                UnmarshallerFactory unmarshallerFactory =
                        Configuration.getUnmarshallerFactory();
                Unmarshaller unmarshaller = unmarshallerFactory
                        .getUnmarshaller(xmlElement);

                try {
                        return (X) unmarshaller.unmarshall(xmlElement);
                } catch (UnmarshallingException e) {
                        throw new RuntimeException("opensaml2 unmarshalling " +
                                "error: " + e.getMessage(), e);
                }
        }

        private void setEndpointAddress(String location) {
                LOG.debug("ws location: " + location);
                if (null == location) {
                        throw new IllegalArgumentException("SAML Artifact " +
                                "Service location URL cannot be null");
                }
                BindingProvider bindingProvider = (BindingProvider) this.port;
                bindingProvider.getRequestContext().put(
                        BindingProvider.ENDPOINT_ADDRESS_PROPERTY, location);
        }

        /*
         * Registers the logging SOAP handler on the given JAX-WS port component.
         */
        protected void registerLoggerHandler() {

                BindingProvider bindingProvider = (BindingProvider) this.port;

                Binding binding = bindingProvider.getBinding();
                @SuppressWarnings("unchecked")
                List<Handler> handlerChain = binding.getHandlerChain();
                handlerChain.add(new LoggingSoapHandler());
                binding.setHandlerChain(handlerChain);
        }

        /*
         * Unregister possible logging SOAP handlers on the given JAX-WS port component.
         */
        protected void removeLoggerHandler() {

                BindingProvider bindingProvider = (BindingProvider) this.port;

                Binding binding = bindingProvider.getBinding();
                @SuppressWarnings("unchecked")
                List<Handler> handlerChain = binding.getHandlerChain();
                Iterator<Handler> iter = handlerChain.iterator();
                while (iter.hasNext()) {
                        Handler handler = iter.next();
                        if (handler instanceof LoggingSoapHandler) {
                                iter.remove();
                        }

                }
        }
}
