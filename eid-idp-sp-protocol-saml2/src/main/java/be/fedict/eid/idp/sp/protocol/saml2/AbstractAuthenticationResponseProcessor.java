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
import org.opensaml.saml2.core.*;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.schema.XSBase64Binary;
import org.opensaml.xml.schema.XSDateTime;
import org.opensaml.xml.schema.XSInteger;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.security.keyinfo.KeyInfoHelper;
import org.opensaml.xml.util.Base64;

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
public abstract class AbstractAuthenticationResponseProcessor {

        private static final String RELAY_STATE_PARAM = "RelayState";

        protected static final Log LOG = LogFactory
                .getLog(AbstractAuthenticationResponseProcessor.class);

        static {
                try {
                        DefaultBootstrap.bootstrap();
                } catch (ConfigurationException e) {
                        throw new RuntimeException("could not bootstrap the OpenSAML2 library", e);
                }
        }

        /**
         * Process the incoming SAML v2.0 response.
         *
         * @param request the HTTP servlet request that holds the SAML2 response.
         * @return the SAML2 {@link AuthenticationResponse}
         * @throws AuthenticationResponseProcessorException
         *          case something went wrong
         */
        public AuthenticationResponse process(HttpServletRequest request)
                throws AuthenticationResponseProcessorException {

                Response samlResponse = getSamlResponse(request);

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
                LOG.debug("issuer: " + assertion.getIssuer().getValue());
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
                AuthenticationResponseService service =
                        getAuthenticationResponseService();
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

                // get signature cert.chain if any and pass along to service
                if (null != samlResponse.getSignature()) {

                        try {
                                List<X509Certificate> certChain =
                                        KeyInfoHelper.getCertificates(samlResponse
                                                .getSignature().getKeyInfo());

                                if (null != service) {
                                        service.validateServiceCertificate(
                                                authenticationPolicy, certChain);
                                }
                        } catch (CertificateException e) {
                                throw new AuthenticationResponseProcessorException(e);
                        }
                }

                Subject subject = assertion.getSubject();
                NameID nameId = subject.getNameID();

                String identifier = nameId.getValue();
                Map<String, Object> attributeMap = new HashMap<String, Object>();
                String relayState = request.getParameter(RELAY_STATE_PARAM);

                List<AttributeStatement> attributeStatements = assertion
                        .getAttributeStatements();
                if (!attributeStatements.isEmpty()) {

                        AttributeStatement attributeStatement = attributeStatements.get(0);

                        // normal attributes
                        List<Attribute> attributes = attributeStatement.getAttributes();
                        for (Attribute attribute : attributes) {
                                String attributeName = attribute.getName();

                                if (attribute.getAttributeValues().get(0) instanceof XSString) {

                                        XSString attributeValue = (XSString) attribute
                                                .getAttributeValues().get(0);
                                        attributeMap.put(attributeName, attributeValue.getValue());

                                } else if (attribute.getAttributeValues().get(0) instanceof XSInteger) {

                                        XSInteger attributeValue = (XSInteger) attribute
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

                        // TODO: encrypted attributes
                }

                return new AuthenticationResponse(authenticationTime,
                        identifier, authenticationPolicy, attributeMap,
                        relayState, assertion);
        }

        protected abstract Response getSamlResponse(HttpServletRequest request)
                throws AuthenticationResponseProcessorException;

        protected abstract AuthenticationResponseService getAuthenticationResponseService();
}
