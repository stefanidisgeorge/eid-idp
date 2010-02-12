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

package be.fedict.eid.idp.protocol.simple;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import be.fedict.eid.applet.service.Address;
import be.fedict.eid.applet.service.Identity;
import be.fedict.eid.idp.sp.protocol.simple.SimpleProtocolConstants;
import be.fedict.eid.idp.spi.IdentityProviderFlow;
import be.fedict.eid.idp.spi.IdentityProviderProtocolService;
import be.fedict.eid.idp.spi.ReturnResponse;

/**
 * A protocol service that implements a very simple eID identification protocol.
 * 
 * @author Frank Cornelis
 * 
 */
public class SimpleProtocolService implements IdentityProviderProtocolService {

	private static final Log LOG = LogFactory
			.getLog(SimpleProtocolService.class);

	public static final String TARGET_URL_SESSION_ATTRIBUTE = SimpleProtocolService.class
			.getName()
			+ ".TargetUrl";

	private void setTargetUrl(String targetUrl, HttpServletRequest request) {
		HttpSession httpSession = request.getSession();
		httpSession.setAttribute(TARGET_URL_SESSION_ATTRIBUTE, targetUrl);
	}

	private String getTargetUrl(HttpSession httpSession) {
		String targetUrl = (String) httpSession
				.getAttribute(TARGET_URL_SESSION_ATTRIBUTE);
		return targetUrl;
	}

	public IdentityProviderFlow handleIncomingRequest(HttpServletRequest request)
			throws Exception {
		LOG.debug("handle incoming request");
		String targetUrl = request.getParameter("Target");
		if (null == targetUrl) {
			throw new IllegalArgumentException("Target parameter required");
		}
		setTargetUrl(targetUrl, request);
		return IdentityProviderFlow.IDENTIFICATION;
	}

	public ReturnResponse handleReturnResponse(HttpSession httpSession,
			Identity identity, Address address, String authenticatedIdentifier,
			HttpServletResponse response) throws Exception {
		LOG.debug("handle return response");
		String targetUrl = getTargetUrl(httpSession);
		ReturnResponse returnResponse = new ReturnResponse(targetUrl);
		returnResponse.addAttribute(
				SimpleProtocolConstants.FIRST_NAME_PARAMETER,
				identity.firstName);
		returnResponse.addAttribute(SimpleProtocolConstants.NAME_PARAMETER,
				identity.name);
		returnResponse.addAttribute(
				SimpleProtocolConstants.MIDDLE_NAME_PARAMETER,
				identity.middleName);
		returnResponse.addAttribute(
				SimpleProtocolConstants.STREET_AND_NUMBER_PARAMETER,
				address.streetAndNumber);
		returnResponse.addAttribute(SimpleProtocolConstants.ZIP_PARAMETER,
				address.zip);
		returnResponse.addAttribute(
				SimpleProtocolConstants.MUNICIPALITY_PARAMETER,
				address.municipality);
		return returnResponse;
	}
}
