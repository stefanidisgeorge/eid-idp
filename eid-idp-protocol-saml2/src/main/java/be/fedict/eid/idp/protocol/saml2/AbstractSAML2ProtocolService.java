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

package be.fedict.eid.idp.protocol.saml2;

import be.fedict.eid.idp.common.AttributeConstants;
import be.fedict.eid.idp.common.saml2.Saml2Util;
import be.fedict.eid.idp.spi.Attribute;
import be.fedict.eid.idp.spi.*;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.common.binding.decoding.SAMLMessageDecoder;
import org.opensaml.saml2.binding.decoding.HTTPPostDecoder;
import org.opensaml.saml2.core.*;
import org.opensaml.ws.transport.OutTransport;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.security.x509.X509KeyInfoGeneratorFactory;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * SAML2 Browser POST Profile protocol service.
 *
 * @author Frank Cornelis
 */
public abstract class AbstractSAML2ProtocolService implements IdentityProviderProtocolService {

        private static final Log LOG = LogFactory
                .getLog(AbstractSAML2ProtocolService.class);

        private IdentityProviderConfiguration configuration;

        public static final String TARGET_URL_SESSION_ATTRIBUTE = AbstractSAML2ProtocolService.class
                .getName()
                + ".TargetUrl";

        public static final String RELAY_STATE_SESSION_ATTRIBUTE = AbstractSAML2ProtocolService.class
                .getName()
                + ".RelayState";

        public static final String IN_RESPONSE_TO_SESSION_ATTRIBUTE = AbstractSAML2ProtocolService.class
                .getName()
                + ".InResponseTo";

        private void setTargetUrl(String targetUrl, HttpServletRequest request) {
                HttpSession httpSession = request.getSession();
                httpSession.setAttribute(TARGET_URL_SESSION_ATTRIBUTE, targetUrl);
        }

        private String getTargetUrl(HttpSession httpSession) {
                return (String) httpSession
                        .getAttribute(TARGET_URL_SESSION_ATTRIBUTE);
        }

        private void setInResponseTo(String inResponseTo, HttpServletRequest request) {
                HttpSession httpSession = request.getSession();
                httpSession
                        .setAttribute(IN_RESPONSE_TO_SESSION_ATTRIBUTE, inResponseTo);
        }

        private String getInResponseTo(HttpSession httpSession) {
                return (String) httpSession
                        .getAttribute(IN_RESPONSE_TO_SESSION_ATTRIBUTE);
        }

        private void setRelayState(String relayState, HttpServletRequest request) {
                HttpSession httpSession = request.getSession();
                httpSession.setAttribute(RELAY_STATE_SESSION_ATTRIBUTE, relayState);
        }

        private String getRelayState(HttpSession httpSession) {
                return (String) httpSession
                        .getAttribute(RELAY_STATE_SESSION_ATTRIBUTE);
        }

        @Override
        public String getId() {

                LOG.debug("get ID");
                return "SAML2";
        }

        @SuppressWarnings("unchecked")
        @Override
        public void init(ServletContext servletContext,
                         IdentityProviderConfiguration configuration) {

                LOG.debug("init");
                this.configuration = configuration;

                try {
                        DefaultBootstrap.bootstrap();

                } catch (ConfigurationException e) {
                        throw new RuntimeException("OpenSAML configuration error: "
                                + e.getMessage(), e);
                }
        }

        @Override
        public IncomingRequest handleIncomingRequest(
                HttpServletRequest request, HttpServletResponse response)
                throws Exception {

                LOG.debug("handling incoming request");

                if (!request.getMethod().equals("POST")) {
                        throw new ServletException("Only HTTP POST allowed.");
                }

                BasicSAMLMessageContext<SAMLObject, SAMLObject, SAMLObject> messageContext =
                        new BasicSAMLMessageContext<SAMLObject, SAMLObject, SAMLObject>();
                messageContext
                        .setInboundMessageTransport(new HttpServletRequestAdapter(
                                request));

                SAMLMessageDecoder decoder = new HTTPPostDecoder();
                decoder.decode(messageContext);

                SAMLObject samlObject = messageContext.getInboundSAMLMessage();
                LOG.debug("SAML object class: " + samlObject.getClass().getName());
                if (!(samlObject instanceof AuthnRequest)) {
                        throw new IllegalArgumentException(
                                "expected a SAML2 AuthnRequest document");
                }
                AuthnRequest authnRequest = (AuthnRequest) samlObject;

                // optionally authenticate RP
                String issuer = authnRequest.getIssuer().getValue();

                String targetUrl = authnRequest.getAssertionConsumerServiceURL();
                LOG.debug("target URL: " + targetUrl);
                setTargetUrl(targetUrl, request);

                String relayState = messageContext.getRelayState();
                setRelayState(relayState, request);

                String inResponseTo = authnRequest.getID();
                setInResponseTo(inResponseTo, request);

                LOG.debug("request: " + Saml2Util.domToString(
                        Saml2Util.marshall(authnRequest).getOwnerDocument(), true));

                // Signature validation
                X509Certificate certificate = null;
                if (null != authnRequest.getSignature()) {

                        List<X509Certificate> certChain =
                                Saml2Util.validateSignature(authnRequest.getSignature());
                        certificate = Saml2Util.getEndCertificate(certChain);
                }

                return new IncomingRequest(getAuthenticationFlow(), issuer,
                        certificate);

        }

        @SuppressWarnings("unchecked")
        @Override
        public ReturnResponse handleReturnResponse(HttpSession httpSession,
                                                   String userId,
                                                   Map<String, Attribute> attributes,
                                                   HttpServletRequest request,
                                                   HttpServletResponse response)
                throws Exception {
                LOG.debug("handle return response");
                LOG.debug("userId: " + userId);
                String targetUrl = getTargetUrl(httpSession);
                String relayState = getRelayState(httpSession);
                String inResponseTo = getInResponseTo(httpSession);

                Response samlResponse = Saml2Util.buildXMLObject(Response.class,
                        Response.DEFAULT_ELEMENT_NAME);
                DateTime issueInstant = new DateTime();
                samlResponse.setIssueInstant(issueInstant);
                samlResponse.setVersion(SAMLVersion.VERSION_20);
                samlResponse.setDestination(targetUrl);
                String samlResponseId = "saml-response-" + UUID.randomUUID().toString();
                samlResponse.setID(samlResponseId);

                Status status = Saml2Util.buildXMLObject(Status.class,
                        Status.DEFAULT_ELEMENT_NAME);
                samlResponse.setStatus(status);
                StatusCode statusCode = Saml2Util.buildXMLObject(StatusCode.class,
                        StatusCode.DEFAULT_ELEMENT_NAME);
                status.setStatusCode(statusCode);
                statusCode.setValue(StatusCode.SUCCESS_URI);

                // generate assertion
                Assertion assertion = Saml2Util.getAssertion(inResponseTo,
                        targetUrl, issueInstant, getAuthenticationFlow(),
                        userId, attributes);

                // sign assertion
                KeyStore.PrivateKeyEntry idpIdentity = this.configuration.findIdentity();
                if (null != idpIdentity) {
                        Saml2Util.sign(assertion, idpIdentity);
                }

                samlResponse.getAssertions().add(assertion);

                ReturnResponse returnResponse = new ReturnResponse(targetUrl);

                HTTPPostEncoder messageEncoder = new HTTPPostEncoder();
                BasicSAMLMessageContext messageContext = new BasicSAMLMessageContext();
                messageContext.setOutboundSAMLMessage(samlResponse);
                messageContext.setRelayState(relayState);

                // sign response
                if (null != idpIdentity) {

                        BasicX509Credential credential = new BasicX509Credential();
                        credential.setPrivateKey(idpIdentity.getPrivateKey());
                        credential.setEntityCertificateChain(this.configuration.getIdentityCertificateChain());

                        // enable adding the cert.chain as KeyInfo
                        X509KeyInfoGeneratorFactory factory =
                                (X509KeyInfoGeneratorFactory) Configuration.getGlobalSecurityConfiguration().
                                        getKeyInfoGeneratorManager().getDefaultManager().
                                        getFactory(credential);
                        factory.setEmitEntityCertificateChain(true);

                        messageContext.setOutboundSAMLMessageSigningCredential(credential);
                }
                OutTransport outTransport = new HTTPOutTransport(returnResponse);
                messageContext.setOutboundMessageTransport(outTransport);

                messageEncoder.encode(messageContext);
                return returnResponse;
        }

        @Override
        public String findAttributeUri(String uri) {

                DefaultAttribute defaultAttribute = DefaultAttribute.findDefaultAttribute(uri);
                if (null != defaultAttribute) {
                        switch (defaultAttribute) {

                                case LAST_NAME:
                                        return AttributeConstants.LAST_NAME_CLAIM_TYPE_URI;
                                case FIRST_NAME:
                                        return AttributeConstants.FIRST_NAME_CLAIM_TYPE_URI;
                                case NAME:
                                        return AttributeConstants.NAME_CLAIM_TYPE_URI;
                                case IDENTIFIER:
                                        return AttributeConstants.PPID_CLAIM_TYPE_URI;
                                case ADDRESS:
                                        return AttributeConstants.STREET_ADDRESS_CLAIM_TYPE_URI;
                                case LOCALITY:
                                        return AttributeConstants.LOCALITY_CLAIM_TYPE_URI;
                                case POSTAL_CODE:
                                        return AttributeConstants.POSTAL_CODE_CLAIM_TYPE_URI;
                                case GENDER:
                                        return AttributeConstants.GENDER_CLAIM_TYPE_URI;
                                case DATE_OF_BIRTH:
                                        return AttributeConstants.DATE_OF_BIRTH_CLAIM_TYPE_URI;
                                case NATIONALITY:
                                        return AttributeConstants.NATIONALITY_CLAIM_TYPE_URI;
                                case PLACE_OF_BIRTH:
                                        return AttributeConstants.PLACE_OF_BIRTH_CLAIM_TYPE_URI;
                                case PHOTO:
                                        return AttributeConstants.PHOTO_CLAIM_TYPE_URI;
                        }
                }

                return null;
        }

        protected abstract IdentityProviderFlow getAuthenticationFlow();
}
