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
import be.fedict.eid.idp.sp.protocol.saml2.spi.AuthenticationResponseService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
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
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.keyinfo.KeyInfoHelper;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.validation.ValidationException;

import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Processes the response of the SAML v2.0 protocol.
 * <p/>
 * <p>
 * The following init-params are required:
 * </p>
 * <ul>
 * <li><tt>IdentifierSessionAttribute</tt>: indicates the session attribute to
 * store the returned subject identifier.</li>
 * <li><tt>RedirectPage</tt>: indicates the page where to redirect after
 * successfull authentication.</li>
 * <li><tt>ErrorPage</tt>: indicates the page to be shown in case of errors.</li>
 * <li><tt>ErrorMessageSessionAttribute</tt>: indicates which session attribute
 * to use for reporting an error. This session attribute can be used on the
 * error page.</li>
 * </ul>
 * <p/>
 * <p>
 * The following init-params are optional:
 * </p>
 * <ul>
 * <li><tt>AttributeMapSessionAttribute</tt>: indicates the session attribute to
 * store the map of optionally returned attributes.</li>
 * <li><tt>RelayStateSessionAttribute</tt>: indicates the session attribute to
 * store optionally returned relay state.</li>
 * <li><tt>AuthenticationResponseService</tt>: indicates the JNDI location of
 * the {@link AuthenticationResponseService} that can be used optionally for
 * e.g. validation of the certificate chain in the response's signature.
 * </ul>
 */
public class AuthenticationResponseServlet extends HttpServlet {

        private static final long serialVersionUID = 1L;

        private static final Log LOG = LogFactory
                .getLog(AuthenticationResponseServlet.class);

        public static final String IDENTIFIER_SESSION_ATTRIBUTE_INIT_PARAM =
                "IdentifierSessionAttribute";
        public static final String REDIRECT_PAGE_INIT_PARAM =
                "RedirectPage";

        public static final String ATTRIBUTE_MAP_SESSION_ATTRIBUTE_INIT_PARAM =
                "AttributeMapSessionAttribute";
        public static final String RELAY_STATE_SESSION_ATTRIBUTE_INIT_PARAM =
                "RelayStateSessionAttribute";
        public static final String AUTHENTICATION_RESPONSE_SERVICE_SESSION_ATTRIBUTE_INIT_PARAM =
                "AuthenticationResponseService";

        public static final String ERROR_PAGE_INIT_PARAM = "ErrorPage";
        public static final String ERROR_MESSAGE_SESSION_ATTRIBUTE_INIT_PARAM =
                "ErrorMessageSessionAttribute";


        private String identifierSessionAttribute;
        private String attributeMapSessionAttribute;

        private String redirectPage;
        private String relayStateSessionAttribute;

        private String authenticationResponseService;

        private String errorPage;
        private String errorMessageSessionAttribute;


        @Override
        public void init(ServletConfig config) throws ServletException {

                this.identifierSessionAttribute = getRequiredInitParameter(
                        IDENTIFIER_SESSION_ATTRIBUTE_INIT_PARAM, config);
                this.redirectPage = getRequiredInitParameter(
                        REDIRECT_PAGE_INIT_PARAM, config);

                this.attributeMapSessionAttribute = config
                        .getInitParameter(ATTRIBUTE_MAP_SESSION_ATTRIBUTE_INIT_PARAM);
                this.relayStateSessionAttribute = config
                        .getInitParameter(RELAY_STATE_SESSION_ATTRIBUTE_INIT_PARAM);
                this.authenticationResponseService = config
                        .getInitParameter(AUTHENTICATION_RESPONSE_SERVICE_SESSION_ATTRIBUTE_INIT_PARAM);

                this.errorPage = getRequiredInitParameter(ERROR_PAGE_INIT_PARAM,
                        config);
                this.errorMessageSessionAttribute = getRequiredInitParameter(
                        ERROR_MESSAGE_SESSION_ATTRIBUTE_INIT_PARAM, config);
        }

        private String getRequiredInitParameter(String parameterName,
                                                ServletConfig config) throws ServletException {
                String value = config.getInitParameter(parameterName);
                if (null == value) {
                        throw new ServletException(parameterName
                                + " init-param is required");
                }
                return value;
        }

        @Override
        protected void doGet(HttpServletRequest request,
                             HttpServletResponse response)
                throws ServletException, IOException {

                showErrorPage("SAML2 response handler not available via GET", null,
                        request, response);
        }

        @Override
        @SuppressWarnings("unchecked")
        protected void doPost(HttpServletRequest request,
                              HttpServletResponse response) throws ServletException, IOException {
                LOG.debug("doPost");

                HttpSession httpSession = request.getSession();
                clearAllSessionAttribute(httpSession);

                try {
                        DefaultBootstrap.bootstrap();
                } catch (ConfigurationException e) {
                        showErrorPage("OpenSAML configuration exception", e,
                                request, response);
                        return;
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
                        showErrorPage("OpenSAML message decoding error", e,
                                request, response);
                        return;
                } catch (SecurityException e) {
                        showErrorPage("OpenSAML security error: " + e.getMessage(),
                                e, request, response);
                        return;
                }

                SAMLObject samlObject = messageContext.getInboundSAMLMessage();
                LOG.debug("SAML object class: " + samlObject.getClass().getName());
                if (!(samlObject instanceof Response)) {
                        showErrorPage("expected a SAML2 Response document", null,
                                request, response);
                        return;
                }
                Response samlResponse = (Response) samlObject;

                Status status = samlResponse.getStatus();
                StatusCode statusCode = status.getStatusCode();
                String statusValue = statusCode.getValue();
                if (!StatusCode.SUCCESS_URI.equals(statusValue)) {
                        showErrorPage("no successful SAML response", null,
                                request, response);
                        return;
                }

                List<Assertion> assertions = samlResponse.getAssertions();
                if (assertions.isEmpty()) {
                        showErrorPage("missing SAML assertions", null,
                                request, response);
                        return;
                }

                Assertion assertion = assertions.get(0);
                List<AuthnStatement> authnStatements = assertion.getAuthnStatements();
                if (authnStatements.isEmpty()) {
                        showErrorPage("missing SAML authn statement", null,
                                request, response);
                        return;
                }

                // TODO: validate conditions, configurable timeframe?

                AuthnStatement authnStatement = assertion.getAuthnStatements().get(0);
                // TODO: validate AuthnInstant: authnStatement.getAuthnInstant()
                AuthnContext authnContext = authnStatement.getAuthnContext();
                if (null == authnContext) {
                        showErrorPage("missing SAML authn context", null,
                                request, response);
                        return;
                }
                AuthnContextClassRef authnContextClassRef = authnContext.getAuthnContextClassRef();
                if (null == authnContextClassRef) {
                        showErrorPage("missing SAML authn context ref", null,
                                request, response);
                        return;
                }

                // get authentication policy
                SamlAuthenticationPolicy authenticationPolicy =
                        SamlAuthenticationPolicy.getAuthenticationPolicy(
                                authnContextClassRef.getAuthnContextClassRef());


                // Signature validation
                try {
                        if (null != samlResponse.getSignature()) {
                                List<X509Certificate> certChain =
                                        KeyInfoHelper.getCertificates(
                                                samlResponse.getSignature().getKeyInfo());
                                try {
                                        SAMLSignatureProfileValidator pv =
                                                new SAMLSignatureProfileValidator();
                                        pv.validate(samlResponse.getSignature());
                                        BasicX509Credential credential = new BasicX509Credential();
                                        credential.setPublicKey(certChain.get(0).getPublicKey());
                                        SignatureValidator sigValidator = new SignatureValidator(credential);
                                        sigValidator.validate(samlResponse.getSignature());
                                } catch (ValidationException e) {

                                        showErrorPage("SAML response signature validation error: " + e.getMessage(),
                                                e, request, response);
                                        return;
                                }

                                // validation of the certificate chain in the SAML response's signature.
                                if (null != this.authenticationResponseService) {
                                        AuthenticationResponseService service;
                                        try {
                                                InitialContext initialContext = new InitialContext();
                                                service = (AuthenticationResponseService) initialContext
                                                        .lookup(this.authenticationResponseService);


                                                service.validateServiceCertificate(authenticationPolicy, certChain);

                                        } catch (NamingException e) {
                                                showErrorPage("Error locating AuthenticationResponseService: "
                                                        + e.getMessage(),
                                                        e, request, response);
                                                return;
                                        }
                                }
                        }
                } catch (CertificateException e) {
                        showErrorPage("Failed to get certificates from SAML" +
                                "response signature: " + e.getMessage(),
                                e, request, response);
                        return;
                }


                Subject subject = assertion.getSubject();
                NameID nameId = subject.getNameID();
                String identifier = nameId.getValue();
                httpSession.setAttribute(this.identifierSessionAttribute, identifier);

                List<AttributeStatement> attributeStatements = assertion
                        .getAttributeStatements();
                if (!attributeStatements.isEmpty()) {

                        Map<String, Object> attributeMap = new HashMap<String, Object>();

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
                                        showErrorPage("Unsupported attribute of " +
                                                "type: " + attribute.getAttributeValues().get(0)
                                                .getClass().getName(),
                                                null, request, response);
                                        return;
                                }
                        }

                        if (null != this.attributeMapSessionAttribute) {
                                httpSession.setAttribute(this.attributeMapSessionAttribute,
                                        attributeMap);
                        }

                        if (null != this.relayStateSessionAttribute) {
                                String relayState = request.getParameter("RelayState");
                                LOG.debug("relay state: " + relayState);
                                httpSession.setAttribute(this.relayStateSessionAttribute,
                                        relayState);
                        }
                }

                response.sendRedirect(request.getContextPath() + this.redirectPage);
        }

        private void showErrorPage(String errorMessage, Throwable cause,
                                   HttpServletRequest request, HttpServletResponse response)
                throws IOException, ServletException {

                if (null == cause) {
                        LOG.error("Error: " + errorMessage);
                } else {
                        LOG.error("Error: " + errorMessage, cause);
                }
                request.getSession().setAttribute(
                        this.errorMessageSessionAttribute, errorMessage);
                response.sendRedirect(request.getContextPath() + this.errorPage);
        }

        private void clearAllSessionAttribute(HttpSession httpSession) {

                httpSession.removeAttribute(this.identifierSessionAttribute);
                httpSession.removeAttribute(this.attributeMapSessionAttribute);
                httpSession.removeAttribute(this.relayStateSessionAttribute);
        }
}
