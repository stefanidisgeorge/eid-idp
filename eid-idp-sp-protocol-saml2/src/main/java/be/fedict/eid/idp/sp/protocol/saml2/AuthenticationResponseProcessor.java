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

import be.fedict.eid.idp.common.SamlAuthenticationPolicy;
import be.fedict.eid.idp.sp.protocol.saml2.spi.AuthenticationResponse;
import be.fedict.eid.idp.sp.protocol.saml2.spi.AuthenticationResponseService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.common.binding.decoding.SAMLMessageDecoder;
import org.opensaml.saml2.binding.decoding.HTTPPostDecoder;
import org.opensaml.saml2.core.*;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.schema.XSBase64Binary;
import org.opensaml.xml.schema.XSDateTime;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.security.keyinfo.KeyInfoHelper;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.validation.ValidationException;

import javax.servlet.http.HttpServletRequest;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Processor for SAML v2.0 Responses
 *
 * @author Wim Vandenhaute
 */
public class AuthenticationResponseProcessor {

        private static final Log LOG = LogFactory
                .getLog(AuthenticationResponseProcessor.class);

        /**
         * Process the incoming SAML v2.0 response.
         *
         * @param service optional authentication response service
         * @param request the HTTP servlet request that holds the SAML2 response.
         * @return the SAML2 {@link AuthenticationResponse}
         * @throws AuthenticationResponseProcessorException
         *          case something went wrong
         */
        public AuthenticationResponse process(AuthenticationResponseService service,
                                              HttpServletRequest request)
                throws AuthenticationResponseProcessorException {

                try {
                        DefaultBootstrap.bootstrap();
                } catch (ConfigurationException e) {
                        throw new AuthenticationResponseProcessorException(
                                "OpenSAML configuration exception", e);
                }

                BasicSAMLMessageContext<SAMLObject, SAMLObject, SAMLObject> messageContext =
                        new BasicSAMLMessageContext<SAMLObject, SAMLObject, SAMLObject>();
                messageContext
                        .setInboundMessageTransport(new HttpServletRequestAdapter(
                                request));

                SAMLMessageDecoder decoder = new HTTPPostDecoder();
                try {
                        decoder.decode(messageContext);
                } catch (MessageDecodingException e) {
                        throw new AuthenticationResponseProcessorException(
                                "OpenSAML message decoding error", e);
                } catch (org.opensaml.xml.security.SecurityException e) {
                        throw new AuthenticationResponseProcessorException(
                                "OpenSAML security error: " + e.getMessage(), e);
                }

                SAMLObject samlObject = messageContext.getInboundSAMLMessage();
                LOG.debug("SAML object class: " + samlObject.getClass().getName());
                if (!(samlObject instanceof Response)) {
                        throw new AuthenticationResponseProcessorException(
                                "expected a SAML2 Response document");
                }
                Response samlResponse = (Response) samlObject;

                // validate status
                Status status = samlResponse.getStatus();
                StatusCode statusCode = status.getStatusCode();
                String statusValue = statusCode.getValue();
                if (!StatusCode.SUCCESS_URI.equals(statusValue)) {
                        throw new AuthenticationResponseProcessorException(
                                "no successful SAML response");
                }

                List<Assertion> assertions = samlResponse.getAssertions();
                if (assertions.isEmpty()) {
                        throw new AuthenticationResponseProcessorException(
                                "missing SAML assertions");
                }

                Assertion assertion = assertions.get(0);
                List<AuthnStatement> authnStatements = assertion.getAuthnStatements();
                if (authnStatements.isEmpty()) {
                        throw new AuthenticationResponseProcessorException(
                                "missing SAML authn statement");
                }

                // validate assertion conditions
                DateTime now = new DateTime();
                Conditions conditions = assertion.getConditions();
                DateTime notBefore = conditions.getNotBefore();
                DateTime notOnOrAfter = conditions.getNotOnOrAfter();

                LOG.debug("now: " + now.toString());
                LOG.debug("notBefore: " + notBefore.toString());
                LOG.debug("notOnOrAfter : " + notOnOrAfter.toString());

                int maxOffset = 5;
                if (null != service) {
                        maxOffset = service.getMaximumTimeOffset();
                }
                if (maxOffset >= 0) {
                        if (now.isBefore(notBefore)) {
                                // time skew
                                if (now.plusMinutes(maxOffset).isBefore(notBefore) ||
                                        now.minusMinutes(maxOffset).isAfter(notOnOrAfter)) {
                                        throw new AuthenticationResponseProcessorException(
                                                "SAML2 assertion validation: invalid SAML message timeframe");
                                }
                        } else if (now.isBefore(notBefore) || now.isAfter(notOnOrAfter)) {
                                throw new AuthenticationResponseProcessorException(
                                        "SAML2 assertion validation: invalid SAML message timeframe");
                        }
                }

                // validate authn statement
                AuthnStatement authnStatement = assertion.getAuthnStatements().get(0);
                DateTime authenticationTime = authnStatement.getAuthnInstant();
                AuthnContext authnContext = authnStatement.getAuthnContext();
                if (null == authnContext) {
                        throw new AuthenticationResponseProcessorException(
                                "missing SAML authn context");
                }
                AuthnContextClassRef authnContextClassRef = authnContext.getAuthnContextClassRef();
                if (null == authnContextClassRef) {
                        throw new AuthenticationResponseProcessorException(
                                "missing SAML authn context ref");
                }

                // get authentication policy
                SamlAuthenticationPolicy authenticationPolicy =
                        SamlAuthenticationPolicy.getAuthenticationPolicy(
                                authnContextClassRef.getAuthnContextClassRef());


                // Signature validation
                if (null != samlResponse.getSignature()) {
                        validateSignature(service, samlResponse.getSignature(),
                                authenticationPolicy);
                }

                Subject subject = assertion.getSubject();
                NameID nameId = subject.getNameID();

                String identifier = nameId.getValue();
                Map<String, Object> attributeMap = new HashMap<String, Object>();
                String relayState = request.getParameter("RelayState");

                List<AttributeStatement> attributeStatements = assertion
                        .getAttributeStatements();
                if (!attributeStatements.isEmpty()) {

                        AttributeStatement attributeStatement = attributeStatements.get(0);
                        List<Attribute> attributes = attributeStatement.getAttributes();
                        for (Attribute attribute : attributes) {
                                String attributeName = attribute.getName();

                                if (attribute.getAttributeValues().get(0) instanceof XSString) {

                                        XSString attributeValue = (XSString) attribute
                                                .getAttributeValues().get(0);
                                        attributeMap.put(attributeName, attributeValue.getValue());

                                } else if (attribute.getAttributeValues().get(0) instanceof XSDateTime) {

                                        XSDateTime attributeValue = (XSDateTime) attribute
                                                .getAttributeValues().get(0);
                                        attributeMap.put(attributeName, attributeValue.getValue()
                                                .toDateTime(DateTimeZone.getDefault()));

                                } else if (attribute.getAttributeValues().get(0) instanceof XSBase64Binary) {

                                        XSBase64Binary attributeValue = (XSBase64Binary) attribute
                                                .getAttributeValues().get(0);
                                        attributeMap.put(attributeName,
                                                Base64.decode(attributeValue.getValue()));

                                } else {
                                        throw new AuthenticationResponseProcessorException(
                                                "Unsupported attribute of " +
                                                        "type: " + attribute.getAttributeValues().get(0)
                                                        .getClass().getName());
                                }
                        }
                }

                return new AuthenticationResponse(authenticationTime,
                        identifier, authenticationPolicy, attributeMap,
                        relayState);
        }

        private void validateSignature(AuthenticationResponseService service,
                                       Signature signature,
                                       SamlAuthenticationPolicy authenticationPolicy)
                throws AuthenticationResponseProcessorException {

                try {
                        List<X509Certificate> certChain =
                                KeyInfoHelper.getCertificates(signature.getKeyInfo());
                        try {
                                SAMLSignatureProfileValidator pv =
                                        new SAMLSignatureProfileValidator();
                                pv.validate(signature);
                                BasicX509Credential credential = new BasicX509Credential();
                                credential.setPublicKey(certChain.get(0).getPublicKey());
                                SignatureValidator sigValidator = new SignatureValidator(credential);
                                sigValidator.validate(signature);
                        } catch (ValidationException e) {

                                throw new AuthenticationResponseProcessorException(
                                        "SAML response signature validation error: " + e.getMessage(), e);
                        }

                        // validation of the certificate chain in the SAML response's signature.
                        if (null != service) {
                                service.validateServiceCertificate(authenticationPolicy, certChain);
                        }
                } catch (CertificateException e) {
                        throw new AuthenticationResponseProcessorException(
                                "Failed to get certificates from SAML" +
                                        "response signature: " + e.getMessage(), e);
                }
        }
}
