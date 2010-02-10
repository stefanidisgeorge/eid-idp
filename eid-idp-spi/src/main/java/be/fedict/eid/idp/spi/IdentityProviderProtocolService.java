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

package be.fedict.eid.idp.spi;

import java.util.LinkedList;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import be.fedict.eid.applet.service.Address;
import be.fedict.eid.applet.service.Identity;

/**
 * eID IdP Service Provider Interface for an identification/authentication
 * protocol. Protocol Services are stateless objects. State should be preserved
 * using the HTTP session context.
 * 
 * @author Frank Cornelis
 * 
 */
public interface IdentityProviderProtocolService {

	/**
	 * The possible internal flows provided by the eID IdP.
	 * 
	 */
	public enum IdentityProviderFlow {
		IDENTIFICATION, AUTHENTICATION, AUTHENTICATION_WITH_IDENTIFICATION;
	};

	/**
	 * Handles an incoming request for this protocol.
	 * 
	 * @param request
	 *            the HTTP request.
	 * @return the flow to be continued in the IdP.
	 * 
	 * @throws Exception
	 *             in case this protocol service cannot handle the incoming
	 *             request.
	 */
	IdentityProviderFlow handleIncomingRequest(HttpServletRequest request)
			throws Exception;

	/**
	 * The return response. This is used to construct a Browser POST to get back
	 * to the Service Provider.
	 */
	public static class ReturnResponse {
		private final String actionUrl;
		private final List<Attribute> attributes;

		public ReturnResponse(String actionUrl) {
			this.actionUrl = actionUrl;
			this.attributes = new LinkedList<Attribute>();
		}

		public void addAttribute(String name, String value) {
			Attribute attribute = new Attribute(name, value);
			this.attributes.add(attribute);
		}

		public String getActionUrl() {
			return this.actionUrl;
		}

		public List<Attribute> getAttributes() {
			return this.attributes;
		}

		public static class Attribute {
			private final String name;
			private final String value;

			public Attribute(String name, String value) {
				this.name = name;
				this.value = value;
			}

			public String getName() {
				return this.name;
			}

			public String getValue() {
				return this.value;
			}
		}
	}

	/**
	 * Handles the outgoing response to return to the Service Provider web
	 * application.
	 * 
	 * @param httpSession
	 *            the HTTP session context.
	 * @param identity
	 *            the eID identity (in case of an eID identification operation,
	 *            else <code>null</code>)
	 * @param address
	 *            the eID address (in case of an eID identification operation,
	 *            else <code>null</code>)
	 * @param authenticatedIdentifier
	 *            contains the user identifier in case of an eID authentication
	 *            operation, else <code>null</code>.
	 * @param response
	 *            the HTTP response.
	 * @return the response object in case a Browser POST should be constructed.
	 *         <code>null</code> in case this protocol service handles the
	 *         response generation itself.
	 * @throws Exception
	 *             in case this protocol service cannot construct the outgoing
	 *             response.
	 */
	ReturnResponse handleReturnResponse(HttpSession httpSession,
			Identity identity, Address address, String authenticatedIdentifier,
			HttpServletResponse response) throws Exception;
}
