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
import be.fedict.eid.idp.common.saml2.Saml2Util;
import be.fedict.eid.idp.sp.protocol.saml2.spi.AuthenticationResponse;
import be.fedict.eid.idp.sp.protocol.saml2.spi.AuthenticationResponseService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.*;
import org.opensaml.saml2.encryption.Decrypter;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.encryption.DecryptionException;
import org.opensaml.xml.schema.XSBase64Binary;
import org.opensaml.xml.schema.XSDateTime;
import org.opensaml.xml.schema.XSInteger;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.security.keyinfo.KeyInfoHelper;
import org.opensaml.xml.util.Base64;

import javax.crypto.SecretKey;
import javax.servlet.http.HttpServletRequest;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Processor for SAML v2.0 Responses, used by
 * {@link AbstractAuthenticationResponseServlet}
 * <p/>
 * Will process the SAML v2.0 Response returned by the HTTP-POST
 * {@link be.fedict.eid.idp.sp.protocol.saml2.post.AuthenticationResponseProcessor}
 * and HTTP-Arfifact
 * {@link be.fedict.eid.idp.sp.protocol.saml2.artifact.AuthenticationResponseProcessor}
 * implementations of this processor.
 * <p/>
 * On complete of this response, will returned an {@link AuthenticationResponse}
 * containing all available details of the authenticated subject.
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
         * @param requestId  AuthnRequest.ID, should match response's InResponseTo
         * @param recipient  recipient, should match response's
         *                   Subject.SubjectConfirmation.Recipient
         * @param relayState optional expected relay state
         * @param request    the HTTP servlet request that holds the SAML2 response.
         * @return the SAML2 {@link AuthenticationResponse}
         * @throws AuthenticationResponseProcessorException
         *          case something went wrong
         */
        public AuthenticationResponse process(String requestId, String recipient,
                                              String relayState,
                                              HttpServletRequest request)
                throws AuthenticationResponseProcessorException {

                Response samlResponse = getSamlResponse(request);
                DateTime now = new DateTime();

                // validate InResponseTo
                if (!samlResponse.getInResponseTo().equals(requestId)) {

                        throw new AuthenticationResponseProcessorException(
                                "SAML Response not belonging to AuthnRequest!");
                }

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
                validateConditions(now, assertion.getConditions(), recipient);

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

                                if (null != getAuthenticationResponseService()) {
                                        getAuthenticationResponseService().
                                                validateServiceCertificate(
                                                        authenticationPolicy,
                                                        certChain);
                                }
                        } catch (CertificateException e) {
                                throw new AuthenticationResponseProcessorException(e);
                        }
                }

                Subject subject = assertion.getSubject();
                NameID nameId = subject.getNameID();

                // validate subject confirmation
                validateSubjectConfirmation(subject, requestId, recipient, now);

                // validate optional relaystate
                String returnedRelayState = request.getParameter(RELAY_STATE_PARAM);
                if (null != relayState) {
                        if (!relayState.equals(returnedRelayState)) {
                                throw new AuthenticationResponseProcessorException(
                                        "Returned RelayState does not match original RelayState");
                        }
                } else {
                        if (null != returnedRelayState) {
                                throw new AuthenticationResponseProcessorException(
                                        "Did not expect RelayState to be returned.");
                        }
                }

                String identifier = nameId.getValue();
                Map<String, Object> attributeMap = new HashMap<String, Object>();

                List<AttributeStatement> attributeStatements = assertion
                        .getAttributeStatements();
                if (!attributeStatements.isEmpty()) {

                        AttributeStatement attributeStatement = attributeStatements.get(0);

                        // normal attributes
                        List<Attribute> attributes = attributeStatement.getAttributes();
                        for (Attribute attribute : attributes) {

                                processAttribute(attribute, attributeMap);
                        }

                        // encrypted attributes
                        if (!attributeStatement.getEncryptedAttributes().isEmpty()) {

                                Decrypter decrypter = getDecrypter();

                                for (EncryptedAttribute encryptedAttribute :
                                        attributeStatement.getEncryptedAttributes()) {

                                        try {
                                                Attribute attribute =
                                                        decrypter.decrypt(encryptedAttribute);
                                                LOG.debug("decrypted attribute: "
                                                        + attribute.getName());
                                                processAttribute(attribute, attributeMap);

                                        } catch (DecryptionException e) {
                                                throw new
                                                        AuthenticationResponseProcessorException(e);
                                        }
                                }
                        }


                }

                return new AuthenticationResponse(authenticationTime,
                        identifier, authenticationPolicy, attributeMap,
                        relayState, assertion);
        }

        private void validateConditions(DateTime now, Conditions conditions,
                                        String recipient)
                throws AuthenticationResponseProcessorException {

                // time validation
                validateTime(now, conditions.getNotBefore(),
                        conditions.getNotOnOrAfter());

                // audience restriction
                if (conditions.getAudienceRestrictions().isEmpty() ||
                        conditions.getAudienceRestrictions().size() != 1) {

                        throw new AuthenticationResponseProcessorException(
                                "Expect exactly 1 audience restriction but got " +
                                        "0 or more");
                }
                AudienceRestriction audienceRestriction =
                        conditions.getAudienceRestrictions().get(0);
                if (audienceRestriction.getAudiences().isEmpty() ||
                        audienceRestriction.getAudiences().size() != 1) {

                        throw new AuthenticationResponseProcessorException(
                                "Expect exactly 1 audience but got 0 or more");
                }

                Audience audience = audienceRestriction.getAudiences().get(0);
                if (!audience.getAudienceURI().equals(recipient)) {

                        throw new AuthenticationResponseProcessorException(
                                "AudienceURI does not match expected recipient");
                }

                // OneTimeUse
                if (null == conditions.getOneTimeUse()) {

                        throw new AuthenticationResponseProcessorException(
                                "Assertion is not one-time-use.");
                }
        }

        private void validateSubjectConfirmation(Subject subject,
                                                 String requestId,
                                                 String recipient,
                                                 DateTime now)
                throws AuthenticationResponseProcessorException {

                if (subject.getSubjectConfirmations().isEmpty() ||
                        subject.getSubjectConfirmations().size() != 1) {

                        throw new AuthenticationResponseProcessorException(
                                "Expected exactly 1 SubjectConfirmation but got 0 or more");
                }
                SubjectConfirmation subjectConfirmation =
                        subject.getSubjectConfirmations().get(0);

                // method
                if (!subjectConfirmation.getMethod().equals(SubjectConfirmation.METHOD_BEARER)) {

                        throw new AuthenticationResponseProcessorException(
                                "Subjectconfirmation method: " +
                                        subjectConfirmation.getMethod() +
                                        " is not supported.");
                }

                SubjectConfirmationData subjectConfirmationData =
                        subjectConfirmation.getSubjectConfirmationData();

                // InResponseTo
                if (!subjectConfirmationData.getInResponseTo().equals(requestId)) {

                        throw new AuthenticationResponseProcessorException(
                                "SubjectConfirmationData not belonging to " +
                                        "AuthnRequest!");
                }

                // recipient
                if (!subjectConfirmationData.getRecipient().equals(recipient)) {

                        throw new AuthenticationResponseProcessorException(
                                "SubjectConfirmationData recipient does not " +
                                        "match expected recipient");
                }

                // time validation
                validateTime(now, subjectConfirmationData.getNotBefore(),
                        subjectConfirmationData.getNotOnOrAfter());
        }

        private void validateTime(DateTime now, DateTime notBefore,
                                  DateTime notOnOrAfter)
                throws AuthenticationResponseProcessorException {

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
        }

        private void processAttribute(Attribute attribute,
                                      Map<String, Object> attributeMap)
                throws AuthenticationResponseProcessorException {

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

        private Decrypter getDecrypter()
                throws AuthenticationResponseProcessorException {

                SecretKey secretKey =
                        getAuthenticationResponseService()
                                .getAttributeSecretKey();
                PrivateKey privateKey =
                        getAuthenticationResponseService()
                                .getAttributePrivateKey();

                if (null == secretKey && null == privateKey) {
                        throw new AuthenticationResponseProcessorException(
                                "Encrypted attributes were returned but " +
                                        "no decryption keys were specified.");
                }

                if (null != privateKey) {
                        return Saml2Util.getDecrypter(privateKey);
                }

                return Saml2Util.getDecrypter(secretKey);
        }

        /**
         * @param request HTTP Servlet Request
         * @return the SAML v2.0 Response
         * @throws AuthenticationResponseProcessorException
         *          something went wrong
         *          getting the SAML v2.0 Response
         */
        protected abstract Response getSamlResponse(HttpServletRequest request)
                throws AuthenticationResponseProcessorException;

        /**
         * @return the (optional for HTTP-POST)
         *         {@link AuthenticationResponseService} used for e.g.
         *         validation of the optional signature on the response, ...
         */
        protected abstract AuthenticationResponseService getAuthenticationResponseService();
}
