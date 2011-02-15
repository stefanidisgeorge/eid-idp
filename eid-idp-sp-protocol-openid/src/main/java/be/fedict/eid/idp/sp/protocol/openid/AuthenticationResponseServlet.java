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

package be.fedict.eid.idp.sp.protocol.openid;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.openid4java.association.AssociationException;
import org.openid4java.consumer.ConsumerManager;
import org.openid4java.consumer.VerificationResult;
import org.openid4java.discovery.DiscoveryException;
import org.openid4java.discovery.DiscoveryInformation;
import org.openid4java.discovery.Identifier;
import org.openid4java.message.Message;
import org.openid4java.message.MessageException;
import org.openid4java.message.MessageExtension;
import org.openid4java.message.ParameterList;
import org.openid4java.message.ax.AxMessage;
import org.openid4java.message.ax.FetchResponse;
import org.openid4java.message.pape.PapeResponse;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;

/**
 * OpenID Authentication Response Servlet.
 * <p/>
 * This servlet will process the incoming OpenID "ID Resolution" and construct
 * a {@link OpenIDAuthenticationResponse} from it, putting on the requested
 * HTTP Session parameter. After this it will redirect to the configured
 * redirect page
 * <p/>
 * Required intialization parameters are:
 * <ul>
 * <li><tt>ResponseSessionAttribute</tt>: HTTP Session Attribute on which the
 * {@link OpenIDAuthenticationResponse} will be set.</li>
 * <li><tt>RedirectPage</tt>: Page to redirect to after having processed the
 * OpenID ID Resolution response</li>
 * </ul>
 */
public class AuthenticationResponseServlet extends HttpServlet {

        private static final long serialVersionUID = 1L;

        private static final Log LOG = LogFactory
                .getLog(AuthenticationResponseServlet.class);

        private String responseSessionAttribute;

        private String redirectPage;

        /**
         * {@inheritDoc}
         */
        @Override
        public void init(ServletConfig config) throws ServletException {
                this.responseSessionAttribute = getRequiredInitParameter(
                        "ResponseSessionAttribute", config);
                this.redirectPage = getRequiredInitParameter("RedirectPage", config);
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

        /**
         * {@inheritDoc}
         */
        @Override
        protected void doGet(HttpServletRequest request,
                             HttpServletResponse response) throws ServletException, IOException {
                LOG.debug("doGet: size=" + request.getQueryString().length());
                String openIdMode = request.getParameter("openid.mode");
                if ("id_res".equals(openIdMode)) {
                        try {
                                doIdRes(request, response);
                        } catch (Exception e) {
                                throw new ServletException("OpenID error: " + e.getMessage(), e);
                        }
                }
        }

        @SuppressWarnings("unchecked")
        private void doIdRes(HttpServletRequest request,
                             HttpServletResponse response) throws MessageException,
                DiscoveryException, AssociationException, IOException {
                LOG.debug("id_res");
                LOG.debug("request URL: " + request.getRequestURL());
                ParameterList parameterList = new ParameterList(request
                        .getParameterMap());
                DiscoveryInformation discovered = (DiscoveryInformation) request
                        .getSession().getAttribute("openid-disc");
                LOG.debug("request context path: " + request.getContextPath());
                LOG.debug("request URI: " + request.getRequestURI());
                String receivingUrl = request.getScheme() + "://"
                        + request.getServerName() + ":" + request.getLocalPort()
                        + request.getRequestURI();
                String queryString = request.getQueryString();
                if (queryString != null && queryString.length() > 0) {
                        receivingUrl += "?" + queryString;
                }
                LOG.debug("receiving url: " + receivingUrl);
                ConsumerManager consumerManager = AuthenticationRequestServlet
                        .getConsumerManager(request);
                VerificationResult verificationResult = consumerManager.verify(
                        receivingUrl, parameterList, discovered);
                Identifier identifier = verificationResult.getVerifiedId();
                if (null != identifier) {

                        Date authenticationTime = null;
                        String userId = identifier.getIdentifier();
                        List<String> authnPolicies = new LinkedList<String>();
                        Map<String, Object> attributeMap = new HashMap<String, Object>();
                        LOG.debug("userId: " + userId);
                        Message authResponse = verificationResult.getAuthResponse();

                        // AX
                        if (authResponse.hasExtension(AxMessage.OPENID_NS_AX)) {

                                MessageExtension messageExtension = authResponse
                                        .getExtension(AxMessage.OPENID_NS_AX);
                                if (messageExtension instanceof FetchResponse) {


                                        FetchResponse fetchResponse =
                                                (FetchResponse) messageExtension;

                                        Map<String, String> attributeTypes = fetchResponse.getAttributeTypes();
                                        for (Map.Entry<String, String> entry : attributeTypes.entrySet()) {
                                                attributeMap.put(entry.getValue(),
                                                        fetchResponse.getAttributeValue(entry.getKey()));
                                        }

                                }

                        }

                        // PAPE
                        if (authResponse.hasExtension(PapeResponse.OPENID_NS_PAPE)) {

                                MessageExtension messageExtension = authResponse
                                        .getExtension(PapeResponse.OPENID_NS_PAPE);
                                if (messageExtension instanceof PapeResponse) {

                                        PapeResponse papeResponse =
                                                (PapeResponse) messageExtension;

                                        authnPolicies = papeResponse.getAuthPoliciesList();
                                        authenticationTime = papeResponse.getAuthDate();

                                }
                        }

                        OpenIDAuthenticationResponse openIDAuthenticationResponse =
                                new OpenIDAuthenticationResponse(authenticationTime,
                                        userId, authnPolicies, attributeMap);
                        request.getSession().setAttribute(this.responseSessionAttribute,
                                openIDAuthenticationResponse);

                        response.sendRedirect(request.getContextPath() + this.redirectPage);
                } else {
                        LOG.warn("no verified identifier");
                }
        }
}
