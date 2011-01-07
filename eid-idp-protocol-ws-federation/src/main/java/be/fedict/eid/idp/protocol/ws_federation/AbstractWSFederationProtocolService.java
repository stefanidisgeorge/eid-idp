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

package be.fedict.eid.idp.protocol.ws_federation;

import be.fedict.eid.applet.service.Address;
import be.fedict.eid.applet.service.Identity;
import be.fedict.eid.idp.common.saml2.Saml2Util;
import be.fedict.eid.idp.spi.IdentityProviderConfiguration;
import be.fedict.eid.idp.spi.IdentityProviderFlow;
import be.fedict.eid.idp.spi.IdentityProviderProtocolService;
import be.fedict.eid.idp.spi.ReturnResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.ws.wstrust.*;
import org.w3c.dom.Element;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.xml.transform.TransformerException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

/**
 * WS-Federation Web (Passive) Requestors. We could use OpenAM (OpenSS0), but
 * then again they're also just doing a wrapping around the JAXB classes.
 *
 * @author Frank Cornelis
 */
public abstract class AbstractWSFederationProtocolService implements
        IdentityProviderProtocolService {

    private static final Log LOG = LogFactory
            .getLog(AbstractWSFederationProtocolService.class);

    public static final String WCTX_SESSION_ATTRIBUTE =
            AbstractWSFederationProtocolService.class.getName() + ".wctx";

    public static final String WTREALM_SESSION_ATTRIBUTE =
            AbstractWSFederationProtocolService.class.getName() + ".wtrealm";

    private IdentityProviderConfiguration configuration;

    private void storeWCtx(String wctx, HttpServletRequest request) {
        HttpSession httpSession = request.getSession();
        httpSession.setAttribute(WCTX_SESSION_ATTRIBUTE, wctx);
    }

    private String retrieveWctx(HttpSession httpSession) {
        return (String) httpSession.getAttribute(WCTX_SESSION_ATTRIBUTE);
    }

    private void storeWtrealm(String wtrealm, HttpServletRequest request) {
        HttpSession httpSession = request.getSession();
        httpSession.setAttribute(WTREALM_SESSION_ATTRIBUTE, wtrealm);
    }

    private String retrieveWtrealm(HttpSession httpSession) {
        return (String) httpSession
                .getAttribute(WTREALM_SESSION_ATTRIBUTE);
    }

    @Override
    public IdentityProviderFlow handleIncomingRequest(
            HttpServletRequest request, HttpServletResponse response)
            throws Exception {
        LOG.debug("handleIncomingRequest");
        String wa = request.getParameter("wa");
        if (null == wa) {
            throw new ServletException("wa parameter missing");
        }
        if (!"wsignin1.0".equals(wa)) {
            throw new ServletException("wa action not \"wsignin1.0\"");
        }
        String wtrealm = request.getParameter("wtrealm");
        if (null == wtrealm) {
            throw new ServletException("missing wtrealm parameter");
        }
        LOG.debug("wtrealm: " + wtrealm);
        storeWtrealm(wtrealm, request);
        String wctx = request.getParameter("wctx");
        LOG.debug("wctx: " + wctx);
        storeWCtx(wctx, request);
        return getAuthenticationFlow();
    }

    @Override
    public ReturnResponse handleReturnResponse(HttpSession httpSession,
                                               String userId,
                                               String givenName, String surName,
                                               Identity identity, Address address,
                                               byte[] photo,
                                               HttpServletRequest request,
                                               HttpServletResponse response)
            throws Exception {
        LOG.debug("handleReturnResponse");
        String wtrealm = retrieveWtrealm(httpSession);
        ReturnResponse returnResponse = new ReturnResponse(wtrealm);
        returnResponse.addAttribute("wa", "wsignin1.0");
        String wctx = retrieveWctx(httpSession);
        returnResponse.addAttribute("wctx", wctx);

        String wresult = getWResult(wctx, wtrealm, userId, givenName, surName,
                identity, address, photo);
        returnResponse.addAttribute("wresult", wresult);
        return returnResponse;
    }

    private String getWResult(String wctx, String wtrealm,
                              String userId,
                              String givenName, String surName,
                              Identity identity,
                              Address address,
                              byte[] photo)
            throws TransformerException, IOException {

        RequestSecurityTokenResponseCollection requestSecurityTokenResponseCollection =
                Saml2Util.buildXMLObject(RequestSecurityTokenResponseCollection.class,
                        RequestSecurityTokenResponseCollection.ELEMENT_NAME);

        RequestSecurityTokenResponse requestSecurityTokenResponse =
                Saml2Util.buildXMLObject(RequestSecurityTokenResponse.class,
                        RequestSecurityTokenResponse.ELEMENT_NAME);
        requestSecurityTokenResponseCollection.getRequestSecurityTokenResponses().
                add(requestSecurityTokenResponse);

        if (null != wctx) {
            requestSecurityTokenResponse.setContext(wctx);
        }

        TokenType tokenType = Saml2Util.buildXMLObject(TokenType.class,
                TokenType.ELEMENT_NAME);
        tokenType.setValue("urn:oasis:names:tc:SAML:2.0:assertion");

        RequestType requestType = Saml2Util.buildXMLObject(RequestType.class,
                RequestType.ELEMENT_NAME);
        requestType.setValue("http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue");

        KeyType keyType = Saml2Util.buildXMLObject(KeyType.class,
                KeyType.ELEMENT_NAME);
        keyType.setValue("http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer");

        RequestedSecurityToken requestedSecurityToken =
                Saml2Util.buildXMLObject(RequestedSecurityToken.class,
                        RequestedSecurityToken.ELEMENT_NAME);

        requestSecurityTokenResponse.getUnknownXMLObjects().add(tokenType);
        requestSecurityTokenResponse.getUnknownXMLObjects().add(requestType);
        requestSecurityTokenResponse.getUnknownXMLObjects().add(keyType);
        requestSecurityTokenResponse.getUnknownXMLObjects().add(requestedSecurityToken);


        DateTime issueInstantDateTime = new DateTime();
        Assertion assertion = Saml2Util.getAssertion(null, wtrealm,
                issueInstantDateTime, getAuthenticationFlow(), userId,
                givenName, surName, identity, address, photo);

        requestedSecurityToken.setUnknownXMLObject(assertion);

        KeyStore.PrivateKeyEntry idpIdentity = this.configuration.findIdentity();

        Element element;
        if (null != idpIdentity) {

            LOG.debug("sign assertion");
            element = Saml2Util.signAsElement(requestSecurityTokenResponseCollection,
                    assertion, (X509Certificate) idpIdentity.getCertificate(),
                    idpIdentity.getPrivateKey());
        } else {

            // TODO: explode here? will fail at RP for sure if not signed so ...
            LOG.warn("assertion NOT signed!");
            element = Saml2Util.marshall(requestSecurityTokenResponseCollection);
        }

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        Saml2Util.writeDocument(element.getOwnerDocument(), outputStream);
        return new String(outputStream.toByteArray());
    }


    @Override
    public void init(ServletContext servletContext,
                     IdentityProviderConfiguration configuration) {
        LOG.debug("init");
        this.configuration = configuration;
    }

    protected abstract IdentityProviderFlow getAuthenticationFlow();
}
