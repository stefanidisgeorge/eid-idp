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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import be.fedict.eid.applet.service.Address;
import be.fedict.eid.applet.service.Identity;
import be.fedict.eid.idp.spi.IdentityProviderProtocolService;

/**
 * SAML2 Browser POST Profile protocol service.
 * 
 * @author Frank Cornelis
 * 
 */
public class SAML2ProtocolService implements IdentityProviderProtocolService {

	private static final Log LOG = LogFactory
			.getLog(SAML2ProtocolService.class);

	public IdentityProviderFlow handleIncomingRequest(HttpServletRequest request)
			throws Exception {
		LOG.debug("handling incoming request");
		// TODO
		return IdentityProviderFlow.AUTHENTICATION_WITH_IDENTIFICATION;
	}

	public ReturnResponse handleReturnResponse(HttpSession httpSession,
			Identity identity, Address address, HttpServletResponse response)
			throws Exception {
		LOG.debug("handle return response");
		// TODO
		return null;
	}

}
