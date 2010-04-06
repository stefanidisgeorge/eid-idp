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

package be.fedict.eid.idp.protocol.openid;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Map;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.openid4java.association.Association;
import org.openid4java.message.AuthRequest;
import org.openid4java.message.AuthSuccess;
import org.openid4java.message.Message;
import org.openid4java.message.MessageException;
import org.openid4java.message.MessageExtension;
import org.openid4java.message.ParameterList;
import org.openid4java.message.ax.AxMessage;
import org.openid4java.message.ax.FetchRequest;
import org.openid4java.message.ax.FetchResponse;
import org.openid4java.message.pape.PapeResponse;
import org.openid4java.server.InMemoryServerAssociationStore;
import org.openid4java.server.RealmVerifier;
import org.openid4java.server.ServerAssociationStore;
import org.openid4java.server.ServerManager;

import be.fedict.eid.applet.service.Address;
import be.fedict.eid.applet.service.Identity;
import be.fedict.eid.idp.spi.IdentityProviderFlow;
import be.fedict.eid.idp.spi.IdentityProviderProtocolService;
import be.fedict.eid.idp.spi.ReturnResponse;

/**
 * OpenID protocol service.
 * 
 * @author Frank Cornelis
 * 
 */
public class OpenIDProtocolService implements IdentityProviderProtocolService {

	private static final Log LOG = LogFactory
			.getLog(OpenIDProtocolService.class);

	public static final String SERVER_MANAGER_ATTRIBUTE = OpenIDProtocolService.class
			.getName()
			+ ".ServerManager";

	private ServerManager getServerManager(HttpServletRequest request) {
		HttpSession httpSession = request.getSession();
		ServletContext servletContext = httpSession.getServletContext();
		ServerManager serverManager = (ServerManager) servletContext
				.getAttribute(SERVER_MANAGER_ATTRIBUTE);
		if (null != serverManager) {
			return serverManager;
		}
		LOG.debug("creating an OpenID server manager");
		serverManager = new ServerManager();
		serverManager
				.setSharedAssociations(new InMemoryServerAssociationStore());
		serverManager
				.setPrivateAssociations(new InMemoryServerAssociationStore());
		String location = "https://" + request.getServerName() + ":"
				+ request.getServerPort() + "/eid-idp";
		String opEndpointUrl = location + "/protocol/openid";
		LOG.debug("OP endpoint URL: " + opEndpointUrl);
		serverManager.setOPEndpointUrl(opEndpointUrl);
		servletContext.setAttribute(SERVER_MANAGER_ATTRIBUTE, serverManager);
		return serverManager;
	}

	public void init(ServletContext servletContext) {
		LOG.debug("init");
	}

	public IdentityProviderFlow handleIncomingRequest(
			HttpServletRequest request, HttpServletResponse response)
			throws Exception {
		LOG.debug("handleIncomingRequest");
		ServerManager serverManager = getServerManager(request);
		ParameterList parameterList = new ParameterList(request
				.getParameterMap());
		String openIdMode = request.getParameter("openid.mode");
		if ("associate".equals(openIdMode)) {
			return doAssociation(response, serverManager, parameterList);
		}
		if ("check_authentication".equals(openIdMode)) {
			return doCheckAuthentication(response, serverManager, parameterList);
		}
		if ("checkid_setup".equals(openIdMode)) {
			return doCheckIdSetup(request, response, serverManager,
					parameterList);
		}
		throw new ServletException("unknown OpenID mode: " + openIdMode);
	}

	private IdentityProviderFlow doCheckIdSetup(HttpServletRequest request,
			HttpServletResponse response, ServerManager serverManager,
			ParameterList parameterList) throws MessageException {
		LOG.debug("checkid_setup");
		RealmVerifier realmVerifier = serverManager.getRealmVerifier();
		AuthRequest authRequest = AuthRequest.createAuthRequest(parameterList,
				realmVerifier);
		// cannot store authRequest since it's not serializable.
		HttpSession httpSession = request.getSession();
		storeParameterList(parameterList, httpSession);
		return IdentityProviderFlow.AUTHENTICATION_WITH_IDENTIFICATION;
	}

	private static final String OPENID_PARAMETER_LIST_SESSION_ATTRIBUTE = OpenIDProtocolService.class
			.getName()
			+ ".ParameterList";

	private void storeParameterList(ParameterList parameterList,
			HttpSession httpSession) {
		httpSession.setAttribute(OPENID_PARAMETER_LIST_SESSION_ATTRIBUTE,
				parameterList);
	}

	private ParameterList retrieveParameterList(HttpSession httpSession) {
		ParameterList parameterList = (ParameterList) httpSession
				.getAttribute(OPENID_PARAMETER_LIST_SESSION_ATTRIBUTE);
		if (null == parameterList) {
			throw new IllegalStateException(
					"missing session OpenID ParameterList");
		}
		return parameterList;
	}

	private IdentityProviderFlow doCheckAuthentication(
			HttpServletResponse response, ServerManager serverManager,
			ParameterList parameterList) throws IOException {
		LOG.debug("check_authentication");
		Message message = serverManager.verify(parameterList);
		String keyValueFormEncoding = message.keyValueFormEncoding();
		response.getWriter().print(keyValueFormEncoding);
		return null;
	}

	private IdentityProviderFlow doAssociation(HttpServletResponse response,
			ServerManager serverManager, ParameterList parameterList)
			throws IOException {
		/*
		 * We should only allow SSL here. Thus also no need for DH,
		 * no-encryption is just fine.
		 */
		LOG.debug("associate");
		Message message = serverManager.associationResponse(parameterList);
		String keyValueFormEncoding = message.keyValueFormEncoding();
		LOG.debug("form encoding: " + keyValueFormEncoding);
		PrintWriter printWriter = response.getWriter();
		printWriter.print(keyValueFormEncoding);
		return null;
	}

	public ReturnResponse handleReturnResponse(HttpSession httpSession,
			Identity identity, Address address, String authenticatedIdentifier,
			HttpServletRequest request, HttpServletResponse response)
			throws Exception {
		LOG.debug("handleReturnResponse");
		ServerManager serverManager = getServerManager(request);
		RealmVerifier realmVerifier = serverManager.getRealmVerifier();
		ParameterList parameterList = retrieveParameterList(httpSession);
		AuthRequest authRequest = AuthRequest.createAuthRequest(parameterList,
				realmVerifier);

		String location = "https://" + request.getServerName() + ":"
				+ request.getServerPort()
				+ "/eid-idp/endpoints/openid-identity";
		String userId = location + "?" + identity.getNationalNumber();
		LOG.debug("user identifier: " + userId);

		Message message = serverManager.authResponse(parameterList, userId,
				userId, true, false);
		if (message instanceof AuthSuccess) {
			AuthSuccess authSuccess = (AuthSuccess) message;
			if (authRequest.hasExtension(AxMessage.OPENID_NS_AX)) {
				MessageExtension messageExtension = authRequest
						.getExtension(AxMessage.OPENID_NS_AX);
				if (messageExtension instanceof FetchRequest) {
					FetchRequest fetchRequest = (FetchRequest) messageExtension;
					Map<String, String> requiredAttributes = fetchRequest
							.getAttributes(true);
					FetchResponse fetchResponse = FetchResponse
							.createFetchResponse();
					for (Map.Entry<String, String> requiredAttribute : requiredAttributes
							.entrySet()) {
						String alias = requiredAttribute.getKey();
						String typeUri = requiredAttribute.getValue();
						LOG.debug("attribute alias: " + alias);
						LOG.debug("attribute typeUri: " + typeUri);
						if ("http://axschema.org/namePerson/first"
								.equals(typeUri)) {
							fetchResponse.addAttribute(alias, typeUri, identity
									.getFirstName());
							continue;
						}
						if ("http://axschema.org/namePerson/last"
								.equals(typeUri)) {
							fetchResponse.addAttribute(alias, typeUri, identity
									.getName());
							continue;
						}
					}
					authSuccess.addExtension(fetchResponse);
					authSuccess
							.setSignExtensions(new String[] { AxMessage.OPENID_NS_AX });
				}
			}
			PapeResponse papeResponse = PapeResponse.createPapeResponse();
			papeResponse
					.setAuthPolicies(PapeResponse.PAPE_POLICY_MULTI_FACTOR_PHYSICAL);
			authSuccess.addExtension(papeResponse);
			/*
			 * We manually sign the auth response as we also want to add our own
			 * attributes.
			 */
			String handle = authRequest.getHandle();
			ServerAssociationStore serverAssociationStore = serverManager
					.getSharedAssociations();
			Association association = serverAssociationStore.load(handle);
			authSuccess.setSignature(association.sign(authSuccess
					.getSignedText()));
		}
		String destinationUrl = message.getDestinationUrl(true);
		LOG.debug("destination URL: " + destinationUrl);
		response.sendRedirect(destinationUrl);
		return null;
	}
}
